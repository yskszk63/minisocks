use core::fmt;
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Socket, Type as SocketType};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
        anyhow::bail!("Unexpected magic number: {b:x}");
    }
    let nauth = buf[1] as usize;
    if nauth > buf.len() {
        write.write_all(&[MAGIC_SOCKS5, 0xFF]).await?;
        anyhow::bail!("buf too small: {nauth} > {}", buf.len());
    }
    read.read_exact(&mut buf[..nauth]).await?;
    if !buf[..nauth].contains(&NO_AUTH) {
        write.write_all(&[MAGIC_SOCKS5, 0xFF]).await?;
        anyhow::bail!("Unsupported auth method.");
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
            other => anyhow::bail!("Unknown CommandCode {other:x}"),
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
            anyhow::bail!("Unexpected magic number: {:x}", buf[0]);
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
}

async fn send_reply<W: AsyncWrite + Unpin>(
    write: &mut W,
    state: u8,
    addr: Option<SocketAddr>, // For some reason, Java's SOCKS implementation does not work well when returning with `DOMAIN_NAME`.
) -> anyhow::Result<()> {
    let mut b = vec![MAGIC_SOCKS5, state, 0x00];
    match addr {
        Some(SocketAddr::V4(addr)) => {
            b.push(0x01);
            b.extend(addr.ip().octets());
            b.extend(addr.port().to_be_bytes());
        }
        Some(SocketAddr::V6(addr)) => {
            b.push(0x04);
            b.extend(addr.ip().octets());
            b.extend(addr.port().to_be_bytes());
        }
        None => {
            b.push(0x01);
            b.extend(Ipv4Addr::UNSPECIFIED.octets());
            b.extend(0u16.to_be_bytes());
        }
    }
    write.write_all(&b).await?;
    Ok(())
}

async fn handshake<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
) -> anyhow::Result<TcpStream> {
    let mut buf = [0; 16];
    authenticate(&mut read, &mut write, &mut buf).await?;

    let request = Request::read(&mut read, &mut buf).await?;
    log::info!("{request:?}");
    if request.command_code != CommandCode::TcpConnect {
        let msg = format!("Not supported {:?}", request.command_code);
        send_reply(&mut write, 0x07, None).await?;
        anyhow::bail!(msg)
    }

    let addr = format!("{}:{}", request.addr, request.port);
    log::info!("Connecting {addr}...");
    let conn = match TcpStream::connect(addr).await {
        Ok(conn) => conn,
        Err(err) => {
            send_reply(&mut write, 0x04, None).await?;
            return Err(err.into());
        }
    };
    send_reply(&mut write, 0x00, Some(conn.local_addr().unwrap())).await?;
    Ok(conn)
}

async fn service(mut source: TcpStream, addr: SocketAddr) {
    log::info!("BEGIN {addr}");

    let (mut read, mut write) = source.split();
    let mut conn = match handshake(&mut read, &mut write).await {
        Ok(conn) => conn,
        Err(err) => {
            log::error!("{err}");
            return;
        }
    };

    if let Err(err) = io::copy_bidirectional(&mut source, &mut conn).await {
        log::error!("ERROR {err}");
        return;
    };
    log::info!("DONE {addr}");
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port = env::var("PORT")
        .unwrap_or_else(|_| "1080".to_string())
        .parse()?;

    let sock = Socket::new(Domain::IPV6, SocketType::STREAM, None)?;
    sock.set_nonblocking(true)?;
    sock.set_only_v6(false)?; // Required to use dual stack sockets on Windows.
    sock.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port).into())?;
    sock.listen(0)?;

    let listener = TcpListener::from_std(sock.into())?;
    log::info!("Listening {} ...", listener.local_addr()?);

    loop {
        let (conn, addr) = listener.accept().await?;
        tokio::spawn(service(conn, addr));
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn test_authenticate_succeeded() {
        let mut buf = [0; 32];
        let r = [0x05, 0x01, 0x00];
        let mut w = vec![];
        authenticate(&mut &r[..], &mut w, &mut buf).await.unwrap();
        assert_eq!(&w, &[0x05, 0x00]);
    }

    #[tokio::test]
    async fn test_authenticate_empty() {
        let mut buf = [0; 32];
        let r = [];
        let mut w = vec![];
        let err = authenticate(&mut &r[..], &mut w, &mut buf)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "early eof");
        assert_eq!(&w, &[]);
    }

    #[tokio::test]
    async fn test_authenticate_unexpected_header() {
        let mut buf = [0; 32];
        let r = [0x00, 0x00];
        let mut w = vec![];
        let err = authenticate(&mut &r[..], &mut w, &mut buf)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Unexpected magic number: 0");
        assert_eq!(&w, &[0x05, 0xFF]);
    }

    #[tokio::test]
    async fn test_authenticate_buf_too_small() {
        let mut buf = [0; 2];
        let r = [0x05, 0x03];
        let mut w = vec![];
        let err = authenticate(&mut &r[..], &mut w, &mut buf)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "buf too small: 3 > 2");
        assert_eq!(&w, &[0x05, 0xFF]);
    }

    #[tokio::test]
    async fn test_authenticate_unsupported() {
        let mut buf = [0; 2];
        let r = [0x05, 0x01, 0x01];
        let mut w = vec![];
        let err = authenticate(&mut &r[..], &mut w, &mut buf)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Unsupported auth method.");
        assert_eq!(&w, &[0x05, 0xFF]);
    }

    #[test]
    fn test_command_code_from() {
        assert_eq!(
            CommandCode::try_from(0x01).unwrap(),
            CommandCode::TcpConnect
        );
        assert_eq!(CommandCode::try_from(0x02).unwrap(), CommandCode::TcpBind);
        assert_eq!(CommandCode::try_from(0x03).unwrap(), CommandCode::UdpPort);
        assert_eq!(
            CommandCode::try_from(0x04).unwrap_err().to_string(),
            "Unknown CommandCode 4"
        );
    }

    #[tokio::test]
    async fn test_request_read_ipv4() {
        let mut buf = [0; 32];
        let r = [0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x01, 0xBB];
        let req = Request::read(&mut &r[..], &mut buf).await.unwrap();
        assert_eq!(req.command_code, CommandCode::TcpConnect);
        if let DestAddr::Ipv4(addr) = req.addr {
            assert_eq!(addr, Ipv4Addr::from_str("127.0.0.1").unwrap())
        } else {
            panic!()
        }
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn test_request_read_domain() {
        let mut buf = [0; 32];
        let r = [0x05, 0x01, 0x00, 0x03, 0x01, 0x61, 0x01, 0xBB];
        let req = Request::read(&mut &r[..], &mut buf).await.unwrap();
        assert_eq!(req.command_code, CommandCode::TcpConnect);
        if let DestAddr::Domain(addr) = req.addr {
            assert_eq!(addr, "a");
        } else {
            panic!()
        }
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn test_request_read_ipv6() {
        let mut buf = [0; 32];
        let r = [
            0x05, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xBB,
        ];
        let req = Request::read(&mut &r[..], &mut buf).await.unwrap();
        assert_eq!(req.command_code, CommandCode::TcpConnect);
        if let DestAddr::Ipv6(addr) = req.addr {
            assert_eq!(addr, Ipv6Addr::from_str("::1").unwrap())
        } else {
            panic!()
        }
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn test_request_read_unexpected_magic() {
        let mut buf = [0; 32];
        let r = [0x04, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x01, 0xBB];
        let err = Request::read(&mut &r[..], &mut buf).await.unwrap_err();
        assert_eq!(err.to_string(), "Unexpected magic number: 4");
    }

    #[tokio::test]
    async fn test_request_read_incorrect_addr() {
        let mut buf = [0; 32];
        let r = [0x05, 0x01, 0x00, 0x02, 0x7F, 0x00, 0x00, 0x01, 0x01, 0xBB];
        let err = Request::read(&mut &r[..], &mut buf).await.unwrap_err();
        assert_eq!(err.to_string(), "Unknown 2");
    }

    #[tokio::test]
    async fn test_request_reply_ipv4() {
        let mut w = vec![];
        send_reply(&mut w, 0x00, Some(([127, 0, 0, 1], 443).into()))
            .await
            .unwrap();

        assert_eq!(
            w,
            [0x05, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x01, 0xBB]
        );
    }

    #[tokio::test]
    async fn test_request_reply_ipv6() {
        let mut w = vec![];
        send_reply(&mut w, 0x00, Some((Ipv6Addr::LOCALHOST, 443).into()))
            .await
            .unwrap();

        assert_eq!(
            w,
            [
                0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xBB
            ]
        );
    }

    #[test]
    fn test_destaddr() {
        assert_eq!(
            DestAddr::Ipv4(Ipv4Addr::from_str("127.0.0.1").unwrap()).to_string(),
            "127.0.0.1"
        );
        assert_eq!(DestAddr::Domain("a".to_string()).to_string(), "a");
        assert_eq!(
            DestAddr::Ipv6(Ipv6Addr::from_str("::1").unwrap()).to_string(),
            "::1"
        );
    }
}
