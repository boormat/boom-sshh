use std::io::Write;
use std::os::unix::net::UnixStream;

fn main() {
    let sock = match std::env::var("SSH_AUTH_SOCK") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("SSH_AUTH_SOCK not set");
            std::process::exit(1);
        }
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: histsend <hostname> <uid> <pid> <command...>");
        std::process::exit(1);
    }

    let payload = args.join(" ");
    let ext_type = b"HISTORY";

    let mut stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("connect: {e}");
            std::process::exit(1);
        }
    };

    // SSH_AGENTC_EXTENSION_REQUEST wire format:
    //   uint32 length   = 1 (type) + 4 (string len) + ext_type.len() + payload.len()
    //   byte   type     = 27
    //   string ext_type = uint32(len) + bytes
    //   byte[] payload  = raw bytes (no length prefix — agent reads to EOF)
    let ext_len = ext_type.len();
    let payload_len = payload.len();
    let msg_len = 1 + 4 + ext_len + payload_len;

    let mut msg = Vec::with_capacity(4 + msg_len);
    msg.extend_from_slice(&(msg_len as u32).to_be_bytes());
    msg.push(27); // SSH_AGENTC_EXTENSION_REQUEST
    msg.extend_from_slice(&(ext_len as u32).to_be_bytes());
    msg.extend_from_slice(ext_type);
    msg.extend_from_slice(payload.as_bytes());

    if let Err(e) = stream.write_all(&msg) {
        eprintln!("write: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_format() {
        let ext_type = b"HISTORY";
        let payload = b"myhost 1000 1234   42  ls -la";
        let ext_len = ext_type.len();
        let payload_len = payload.len();
        let msg_len = 1 + 4 + ext_len + payload_len;

        let mut msg = Vec::with_capacity(4 + msg_len);
        msg.extend_from_slice(&(msg_len as u32).to_be_bytes());
        msg.push(27);
        msg.extend_from_slice(&(ext_len as u32).to_be_bytes());
        msg.extend_from_slice(ext_type);
        msg.extend_from_slice(payload);

        // uint32 length
        assert_eq!(&msg[0..4], &(msg_len as u32).to_be_bytes());
        // type byte
        assert_eq!(msg[4], 27);
        // string length for "HISTORY"
        assert_eq!(&msg[5..9], &7u32.to_be_bytes());
        // extension type
        assert_eq!(&msg[9..16], b"HISTORY");
        // payload
        assert_eq!(&msg[16..], payload);
    }

    #[test]
    fn message_length_correct() {
        let ext_type = b"HISTORY";
        let payload = b"h 0 1   1  pwd";
        let msg_len = 1 + 4 + ext_type.len() + payload.len();

        let mut msg = Vec::new();
        msg.extend_from_slice(&(msg_len as u32).to_be_bytes());
        msg.push(27);
        msg.extend_from_slice(&(ext_type.len() as u32).to_be_bytes());
        msg.extend_from_slice(ext_type);
        msg.extend_from_slice(payload);

        // Total message should be 4 (length field) + msg_len
        assert_eq!(msg.len(), 4 + msg_len);
    }
}
