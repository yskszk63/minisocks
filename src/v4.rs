use core::fmt;
use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const MAGIC: u8 = 0x04;

#[derive(Debug, PartialEq, Eq)]
enum CommandCode {
    TcpConnect,
    TcpBind,
}

impl TryFrom<u8> for CommandCode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => CommandCode::TcpConnect,
            0x02 => CommandCode::TcpBind,
            other => anyhow::bail!("Unknown CommandCode {other:x}"),
        })
    }
}

#[derive(Debug)]
enum DestAddr {
    Ipv4(Ipv4Addr),
    Domain(String),
}

impl fmt::Display for DestAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(addr) => addr.fmt(f),
            Self::Domain(addr) => addr.fmt(f),
        }
    }
}

#[derive(Debug)]
struct Request {
    command_code: CommandCode,
    addr: DestAddr,
    port: u16,
    user: String,
}

async fn read_str<R: AsyncRead + Unpin>(read: &mut R, mut buf: Vec<u8>) -> anyhow::Result<String> {
    loop {
        let b = read.read_u8().await?;
        buf.push(b);
        if b == 0 {
            break;
        }
    }

    Ok(CString::from_vec_with_nul(buf)?
        .to_string_lossy()
        .to_string())
}

impl Request {
    async fn read<S: AsyncRead + Unpin, const N: usize>(
        sock: &mut S,
        buf: &mut [u8; N],
    ) -> anyhow::Result<Self> {
        sock.read_exact(&mut buf[..8]).await?; // command, port, addr, user[0]

        let command_code = buf[0].try_into()?;
        let port = u16::from_be_bytes([buf[1], buf[2]]);
        let addr = Ipv4Addr::from([buf[3], buf[4], buf[5], buf[6]]);

        let user = if buf[7] == 0 {
            "".into()
        } else {
            read_str(sock, vec![buf[7]]).await?
        };

        let addr = match addr.octets() {
            [0x00, 0x00, 0x00, 0x00] => DestAddr::Ipv4(addr),
            [0x00, 0x00, 0x00, _] => {
                let domain = read_str(sock, vec![]).await?;
                DestAddr::Domain(domain)
            }
            _ => DestAddr::Ipv4(addr),
        };

        Ok(Request {
            command_code,
            addr,
            port,
            user,
        })
    }
}

async fn send_reply<W: AsyncWrite + Unpin>(
    write: &mut W,
    state: u8,
    addr: Option<SocketAddr>,
) -> anyhow::Result<()> {
    let mut b = vec![0x00, state];
    match addr {
        Some(SocketAddr::V4(addr)) => {
            b.extend(addr.port().to_be_bytes());
            b.extend(addr.ip().octets());
        }
        _ => {
            b.extend(0u16.to_be_bytes());
            b.extend(Ipv4Addr::UNSPECIFIED.octets());
        }
    }
    write.write_all(&b).await?;
    Ok(())
}

pub(crate) async fn handshake<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
) -> anyhow::Result<TcpStream> {
    let mut buf = [0; 16];

    let request = Request::read(&mut read, &mut buf).await?;
    log::info!("{request:?}");
    let _ = request.user; // FIXME
    if request.command_code != CommandCode::TcpConnect {
        let msg = format!("Not supported {:?}", request.command_code);
        send_reply(&mut write, 0x5b, None).await?;
        anyhow::bail!(msg)
    }

    let addr = format!("{}:{}", request.addr, request.port);
    log::info!("Connecting {addr}...");
    let conn = match TcpStream::connect(addr).await {
        Ok(conn) => conn,
        Err(err) => {
            send_reply(&mut write, 0x5b, None).await?;
            return Err(err.into());
        }
    };
    send_reply(&mut write, 0x5a, Some(conn.local_addr().unwrap())).await?;
    Ok(conn)
}
