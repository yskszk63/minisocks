#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use socket2::{Domain, Socket, Type as SocketType};
use tokio::io::{self, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};

mod v4;
mod v5;

async fn service(mut source: TcpStream, addr: SocketAddr) {
    log::info!("BEGIN {addr}");

    let (mut read, mut write) = source.split();
    let mut conn = match read.read_u8().await {
        Ok(v5::MAGIC) => match v5::handshake(&mut read, &mut write).await {
            Ok(conn) => conn,
            Err(err) => {
                log::error!("{err}");
                return;
            }
        },
        Ok(v4::MAGIC) => match v4::handshake(&mut read, &mut write).await {
            Ok(conn) => conn,
            Err(err) => {
                log::error!("{err}");
                return;
            }
        },
        Ok(v) => {
            log::error!("UNSUPPORTED {v}");
            return;
        }
        Err(err) => {
            log::error!("ERROR {err}");
            return;
        }
    };

    if let Err(err) = io::copy_bidirectional(&mut source, &mut conn).await {
        log::error!("ERROR {err}");
        return;
    };
    log::info!("DONE {addr}");
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Listening port
    #[arg(short, long, env = "PORT", default_value = "1080")]
    port: u16,

    /// Listening IPv4 or IPv6 address.
    #[arg(short, long, default_value = "::")]
    addr: IpAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let sock = match args.addr {
        IpAddr::V4(..) => {
            let sock = Socket::new(Domain::IPV4, SocketType::STREAM, None)?;
            sock
        }
        IpAddr::V6(..) => {
            let sock = Socket::new(Domain::IPV6, SocketType::STREAM, None)?;
            sock.set_only_v6(false)?; // Required to use dual stack sockets on Windows.
            sock
        }
    };
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::new(args.addr, args.port).into())?;
    sock.listen(0)?;

    let listener = TcpListener::from_std(sock.into())?;
    log::info!("Listening {} ...", listener.local_addr()?);

    loop {
        let (conn, addr) = listener.accept().await?;
        tokio::spawn(service(conn, addr));
    }
}
