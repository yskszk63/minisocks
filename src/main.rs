use core::fmt;
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task;

const MAGIC_SOCKS5: u8 = 0x05;
const NO_AUTH: u8 = 0x00;

async fn authenticate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin, const N: usize>(
    read: &mut R,
    write: &mut W,
    buf: &mut [u8; N],
) -> anyhow::Result<()> {
    read.read_exact(&mut buf[..2]).await?;

    if buf[0] != MAGIC_SOCKS5 {
        let b = buf[0];
        write.write_all(&[MAGIC_SOCKS5, 0xFF]).await?;
        anyhow::bail!("{b:x} != {MAGIC_SOCKS5:x}");
    }
    let nauth = buf[1] as usize;
    if nauth > buf.len() {
        write.write_all(&[MAGIC_SOCKS5, 0xFF]).await?;
        anyhow::bail!("{nauth} > {}", buf.len());
    }
    read.read_exact(&mut buf[..nauth]).await?;
    if !buf[..nauth].contains(&NO_AUTH) {
        write.write_all(&[MAGIC_SOCKS5, 0xFF]).await?;
        anyhow::bail!("Not contains {NO_AUTH:x}");
    }

    write.write_all(&[MAGIC_SOCKS5, NO_AUTH]).await?;

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum CommandCode {
    TcpConnect,
    TcpBind,
    UdpPort,
}

impl TryFrom<u8> for CommandCode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => CommandCode::TcpConnect,
            0x02 => CommandCode::TcpBind,
            0x03 => CommandCode::UdpPort,
            other => anyhow::bail!("Unknown {other:x}"),
        })
    }
}

#[derive(Debug)]
enum DestAddr {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

impl fmt::Display for DestAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(addr) => addr.fmt(f),
            Self::Domain(addr) => addr.fmt(f),
            Self::Ipv6(addr) => addr.fmt(f),
        }
    }
}

#[derive(Debug)]
struct Request {
    command_code: CommandCode,
    addr: DestAddr,
    port: u16,
}

impl Request {
    async fn read<S: AsyncRead + Unpin, const N: usize>(
        sock: &mut S,
        buf: &mut [u8; N],
    ) -> anyhow::Result<Self> {
        sock.read_exact(&mut buf[..4]).await?;
        if buf[0] != MAGIC_SOCKS5 {
            anyhow::bail!("{:x} != {MAGIC_SOCKS5:x}", buf[0]);
        }

        let command_code = buf[1].try_into()?;
        let addr = match buf[3] {
            0x01 => {
                let mut addr = [0; 4];
                sock.read_exact(&mut addr).await?;
                DestAddr::Ipv4(addr.into())
            }
            0x03 => {
                let n = sock.read_u8().await? as usize;
                let mut b = vec![0; n];
                sock.read_exact(&mut b).await?;
                let domain = String::from_utf8(b)?;
                DestAddr::Domain(domain)
            }
            0x04 => {
                let mut addr = [0; 16];
                sock.read_exact(&mut addr).await?;
                DestAddr::Ipv6(addr.into())
            }
            other => anyhow::bail!("Unknown {other:x}"),
        };

        let port = sock.read_u16().await?; // be
        Ok(Self {
            command_code,
            addr,
            port,
        })
    }

    async fn reply<W: AsyncWrite + Unpin>(self, write: &mut W, state: u8) -> anyhow::Result<()> {
        let mut b = vec![MAGIC_SOCKS5, state, 0x00];
        match self.addr {
            DestAddr::Ipv4(addr) => {
                b.push(0x01);
                b.extend(addr.octets());
            }
            DestAddr::Domain(addr) => {
                b.push(0x03);
                let mut v = addr.into_bytes();
                b.push(v.len() as u8);
                b.append(&mut v);
            }
            DestAddr::Ipv6(addr) => {
                b.push(0x04);
                b.extend(addr.octets());
            }
        };
        b.extend(self.port.to_be_bytes());
        write.write_all(&b).await?;
        Ok(())
    }
}

async fn handshake<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
) -> anyhow::Result<TcpStream> {
    let mut buf = [0; 16];
    authenticate(&mut read, &mut write, &mut buf).await?;

    let request = Request::read(&mut read, &mut buf).await?;
    if request.command_code != CommandCode::TcpConnect {
        let msg = format!("Not supported {:?}", request.command_code);
        request.reply(&mut write, 0x07).await?;
        anyhow::bail!(msg)
    }

    let addr = format!("{}:{}", request.addr, request.port);
    log::info!("Connecting {addr}...");
    let conn = match TcpStream::connect(addr).await {
        Ok(conn) => conn,
        Err(err) => {
            request.reply(&mut write, 0x04).await?;
            return Err(err.into());
        }
    };
    request.reply(&mut write, 0x00).await?;
    Ok(conn)
}

async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut r: R, mut w: W) {
    if let Err(err) = io::copy(&mut r, &mut w).await {
        log::error!("{err}");
    }
}

async fn service(source: TcpStream) {
    let (mut read, mut write) = source.into_split();

    log::debug!("BEGIN");
    let conn = match handshake(&mut read, &mut write).await {
        Ok(conn) => conn,
        Err(err) => {
            log::error!("{err}");
            return;
        }
    };

    let (r2, w2) = conn.into_split();
    tokio::join!(copy(read, w2), copy(r2, write));
    log::debug!("DONE");
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port = env::var("PORT").unwrap_or_else(|_| "1080".to_string());
    let listener = TcpListener::bind(format!("[::]:{port}")).await?;
    log::info!("Listening {} ...", listener.local_addr()?);

    loop {
        let (conn, addr) = listener.accept().await?;
        log::info!("Accepted {addr}");
        task::spawn(service(conn));
    }
}
