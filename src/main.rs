use std::net::UdpSocket;

struct Message {
    header: DNSHeader,
    questions: Vec<Question>,
}

impl Message {
    fn new(header: DNSHeader) -> Message {
        Message {
            header,
            questions: Vec::new()
        }
    }

    fn add_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.nquestions += 1;
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.header.to_bytes());
        for question in &self.questions {
            buffer.extend_from_slice(&question.to_bytes());
        }

        buffer
    }
}

struct DNSHeader {
    id: u16,
    flags: Flags,
    nquestions: u16,
    nanswers: u16,
    nrrs: u16,
    narrs: u16,
}

impl DNSHeader {
    fn new(id: u16, msg_type: DNSMessageType) -> DNSHeader {
        DNSHeader{
            id,
            flags: Flags::new(msg_type),
            nquestions: 0,
            nanswers: 0,
            nrrs: 0,
            narrs: 0
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.id.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&self.nquestions.to_be_bytes());
        buffer.extend_from_slice(&self.nanswers.to_be_bytes());
        buffer.extend_from_slice(&self.nrrs.to_be_bytes());
        buffer.extend_from_slice(&self.narrs.to_be_bytes());
        buffer
    }
}

struct Question {
    name: String,
    qtype: u16,
    class: u16,
}

impl Question {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&Question::to_labels(&self.name));
        buffer.extend_from_slice(&self.qtype.to_be_bytes());
        buffer.extend_from_slice(&self.class.to_be_bytes());
        buffer
    }

    fn to_labels(domain_name: &str) -> Vec<u8> {
        let mut buffer = Vec::new();
        for label in domain_name.split(".") {
            buffer.push(label.len().try_into().expect("domain name component larger than 255 characters"));
            buffer.extend_from_slice(label.as_bytes());
        }
        buffer.push(0);
        buffer
    }
}

#[allow(dead_code)]
enum DNSMessageType {
    Query = 0,
    Reply
}

#[allow(dead_code)]
enum DNSMessageOpcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
}

struct Flags {
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    rcode: u8
}

impl Flags {
    fn new(qr: DNSMessageType) -> Flags {
        Flags {
            qr: qr as u8,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            rcode: 0
        }
    }

    fn to_be_bytes(&self) -> [u8; 2] {
        let mut bytes = [0; 2];
        bytes[0] = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        bytes[1] = (self.ra << 7) | (self.z << 4) | self.rcode;
        bytes
    }
}

fn handle_connection(socket: &UdpSocket, source: &std::net::SocketAddr, _buffer: &[u8]) {
    let header = DNSHeader::new(1234, DNSMessageType::Reply);
    let mut msg = Message::new(header);
    let question = Question{name: String::from("codecrafters.io"), qtype: 1, class: 1};
    msg.add_question(question);
    let response = msg.to_bytes();

    socket
        .send_to(&response, source)
        .expect("Failed to send response");
}

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                handle_connection(&udp_socket, &source, &buf);
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
