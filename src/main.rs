use std::{
    io::{Error, Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

const NO_CONTENT_RESPONSE: &str = "HTTP/1.1 204\r\n\r\n";

fn main() -> Result<(), Error> {
    let socket = TcpListener::bind("0.0.0.0:8080")?;

    _ = socket
        .incoming()
        .map(Result::unwrap)
        .try_for_each(|mut s| handle(&mut s));

    Ok(())
}

fn handle(socket: &mut TcpStream) -> Result<(), Error> {
    dbg!(&socket);
    socket.set_read_timeout(Some(Duration::from_micros(50)))?;
    socket.set_write_timeout(Some(Duration::from_micros(50)))?;

    let mut buffer = [0u8; 512];
    let len = socket.read(&mut buffer)?;

    println!("{:?}", &buffer[..len]);
    //println!("{:?}", std::str::from_utf8(&buffer[..len]));
    socket.write(NO_CONTENT_RESPONSE.as_bytes())?;
    Ok(())
}
