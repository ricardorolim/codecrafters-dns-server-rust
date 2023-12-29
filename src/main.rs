use std::{net::{UdpSocket, Ipv4Addr}, u8, u16, io::SeekFrom};
use std::io::{Cursor, Read, Seek};

const HEADER_LEN: u16 = 12;


struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Answer>
}

impl Message {
    fn new(header: Header) -> Message {
        Message {
            header,
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }

    fn add_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.nquestions += 1;
    }

    fn add_answer(&mut self, answer: Answer) {
        self.answers.push(answer);
        self.header.nanswers += 1;
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.header.to_bytes());
        for question in &self.questions {
            buffer.extend_from_slice(&question.to_bytes());
        }
        for answer in &self.answers {
            buffer.extend_from_slice(&answer.to_bytes());
        }

        buffer
    }
}

struct Header {
    id: u16,
    flags: Flags,
    nquestions: u16,
    nanswers: u16,
    nrrs: u16,
    narrs: u16,
}

impl Header {
    #[allow(dead_code)]
    fn new(id: u16, msg_type: MessageType) -> Header {
        Header{
            id,
            flags: Flags::new(msg_type),
            nquestions: 0,
            nanswers: 0,
            nrrs: 0,
            narrs: 0
        }
    }

    fn parse(buffer: &[u8]) -> Header {
        let flags = Flags {
            qr: (buffer[2] >> 7).try_into().expect("invalid message type"),
            opcode: buffer[2] >> 3 & 0xf,
            aa: buffer[2] >> 2 & 0x1,
            tc: buffer[2] >> 1 & 0x1,
            rd: buffer[2] & 0x1,
            ra: buffer[3] >> 7,
            z: buffer[3] >> 4 & 0xf,
            rcode: buffer[3] & 0xf,
        };

        Header {
            id: u16::from_be_bytes(buffer[0..2].try_into().unwrap()),
            flags,
            nquestions: u16::from_be_bytes(buffer[4..6].try_into().unwrap()),
            nanswers: u16::from_be_bytes(buffer[6..8].try_into().unwrap()),
            nrrs: u16::from_be_bytes(buffer[8..10].try_into().unwrap()),
            narrs: u16::from_be_bytes(buffer[10..12].try_into().unwrap()),
        }
    }

    fn setrcode(&mut self) {
        self.flags.rcode = if self.flags.opcode == 0 { 0 } else { 4};
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.id.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_bytes());
        buffer.extend_from_slice(&self.nquestions.to_be_bytes());
        buffer.extend_from_slice(&self.nanswers.to_be_bytes());
        buffer.extend_from_slice(&self.nrrs.to_be_bytes());
        buffer.extend_from_slice(&self.narrs.to_be_bytes());
        buffer
    }
}

#[derive(Debug, Clone)]
struct Name {
    name: String
}

impl Name {
    #[allow(dead_code)]
    fn new(name: &str) -> Name {
        Name { name: String::from(name) }
    }

    fn parse<T: Read + Seek>(reader: &mut T) -> Name {
        let mut names: Vec<String> = Vec::new();

        loop {
            let mut len = [0];
            let _ = reader.read_exact(&mut len);
            let len = u8::from_be_bytes(len) as usize;

            if len >> 6 == 0b11 { // compressed
                let mut ptr_bottom = [0];
                let _ = reader.read_exact(&mut ptr_bottom);
                let ptr = (((len as u16) & 0x3f) << 8) | u8::from_be_bytes(ptr_bottom) as u16;

                let label = Name::resolve(ptr, reader);
                names.push(label);
                break;
            } else if len == 0 {
                break;
            }

            let mut label = vec![0; len];
            let _ = reader.read_exact(&mut label);

            let label_str = String::from_utf8(label).unwrap();
            names.push(label_str);
        }

        let name = names.join(".");
        Name { name }
    }

    fn resolve<T: Read + Seek>(ptr: u16, reader: &mut T) -> String {
        let pos = reader.stream_position().unwrap();
        let _ = reader.seek(std::io::SeekFrom::Start(ptr.into()));
        let name = Name::parse(reader).name;
        let _ = reader.seek(SeekFrom::Start(pos));
        name
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        for label in self.name.split(".") {
            buffer.push(label.len().try_into().expect("domain name component larger than 255 characters"));
            buffer.extend_from_slice(label.as_bytes());
        }
        buffer.push(0);
        buffer
    }
}

#[derive(Debug,Copy,Clone)]
enum ResourceType {
    A = 1,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT
}

impl TryFrom<u16> for ResourceType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == ResourceType::A as u16  => Ok(ResourceType::A),
            x if x == ResourceType::NS as u16  => Ok(ResourceType::NS),
            x if x == ResourceType::MD as u16  => Ok(ResourceType::MD),
            x if x == ResourceType::MF as u16  => Ok(ResourceType::MF),
            x if x == ResourceType::CNAME as u16  => Ok(ResourceType::CNAME),
            x if x == ResourceType::SOA as u16  => Ok(ResourceType::SOA),
            x if x == ResourceType::MB as u16  => Ok(ResourceType::MB),
            x if x == ResourceType::MG as u16  => Ok(ResourceType::MG),
            x if x == ResourceType::MR as u16  => Ok(ResourceType::MR),
            x if x == ResourceType::NULL as u16  => Ok(ResourceType::NULL),
            x if x == ResourceType::WKS as u16  => Ok(ResourceType::WKS),
            x if x == ResourceType::PTR as u16  => Ok(ResourceType::PTR),
            x if x == ResourceType::HINFO as u16  => Ok(ResourceType::HINFO),
            x if x == ResourceType::MINFO as u16  => Ok(ResourceType::MINFO),
            x if x == ResourceType::MX as u16  => Ok(ResourceType::MX),
            x if x == ResourceType::TXT as u16  => Ok(ResourceType::TXT),
            _ => Err(()),
        }
    }
}

#[derive(Debug,Copy,Clone)]
enum ResourceClass {
    IN = 1,
    CS,
    CH,
    HS
}

impl TryFrom<u16> for ResourceClass {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == ResourceClass::IN as u16  => Ok(ResourceClass::IN),
            x if x == ResourceClass::CS as u16  => Ok(ResourceClass::CS),
            x if x == ResourceClass::CH as u16  => Ok(ResourceClass::CH),
            x if x == ResourceClass::HS as u16  => Ok(ResourceClass::HS),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
struct Question {
    name: Name,
    rtype: ResourceType,
    class: ResourceClass,
}

impl Question {
    fn parse<T: Read + Seek>(reader: &mut T) -> Question {
        let name = Name::parse(reader);

        let mut buf = [0; 2];
        let _ = reader.read_exact(&mut buf);
        let rtype = u16::from_be_bytes(buf).try_into().unwrap();

        let _ = reader.read_exact(&mut buf);
        let class = u16::from_be_bytes(buf).try_into().unwrap();

        Question {name, rtype, class}
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.name.to_bytes());
        buffer.extend_from_slice(&(self.rtype as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.class as u16).to_be_bytes());
        buffer
    }
}

struct Answer {
    name: Name,
    rtype: ResourceType,
    class: ResourceClass,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>
}

impl Answer {
    #[allow(dead_code)]
    fn parse<T: Read + Seek>(reader: &mut T) -> Answer {
        let name = Name::parse(reader);

        let mut buf = [0; 2];
        let mut buf4 = [0; 4];

        let _ = reader.read_exact(&mut buf);
        let rtype = u16::from_be_bytes(buf).try_into().unwrap();

        let _ = reader.read_exact(&mut buf);
        let class = u16::from_be_bytes(buf).try_into().unwrap();

        let _ = reader.read_exact(&mut buf4);
        let ttl = u32::from_be_bytes(buf4);

        let _ = reader.read_exact(&mut buf);
        let rdlength = u16::from_be_bytes(buf);

        let _ = reader.read_exact(&mut buf4);
        let mut rdata = vec![0; 4];
        rdata[0] = u8::from_be(buf4[0]);
        rdata[1] = u8::from_be(buf4[1]);
        rdata[2] = u8::from_be(buf4[2]);
        rdata[3] = u8::from_be(buf4[3]);

        Answer { name, rtype, class, ttl, rdlength, rdata }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.name.to_bytes());
        buffer.extend_from_slice(&(self.rtype as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.class as u16).to_be_bytes());
        buffer.extend_from_slice(&self.ttl.to_be_bytes());
        buffer.extend_from_slice(&self.rdlength.to_be_bytes());
        buffer.extend_from_slice(&self.rdata);
        buffer
    }
}

#[derive(Copy, Clone)]
enum MessageType {
    Query = 0,
    Reply
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == MessageType::Query as u8  => Ok(MessageType::Query),
            x if x == MessageType::Reply as u8  => Ok(MessageType::Reply),
            _ => Err(()),
        }
    }
}

#[allow(dead_code)]
enum MessageOpcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
}

struct Flags {
    qr: MessageType,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    rcode: u8
}

impl Flags {
    #[allow(dead_code)]
    fn new(qr: MessageType) -> Flags {
        Flags {
            qr,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            rcode: 0
        }
    }

    fn to_bytes(&self) -> [u8; 2] {
        let mut bytes = [0; 2];
        bytes[0] = ((self.qr as u8) << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        bytes[1] = (self.ra << 7) | (self.z << 4) | self.rcode;
        bytes
    }
}

fn handle_connection(socket: &UdpSocket, source: &std::net::SocketAddr, buffer: &[u8]) {
    let header = Header::parse(&buffer[..HEADER_LEN as usize]);
    let nquestions = header.nquestions;

    let mut msg = Message::new(header);

    // reset header to be used in response
    msg.header.flags.qr = MessageType::Reply;
    msg.header.nquestions = 0;
    msg.header.setrcode();

    let mut reader = Cursor::new(buffer);
    let _ = reader.seek(std::io::SeekFrom::Start(HEADER_LEN.into()));

    for _ in 0..nquestions {
        let question = Question::parse(&mut reader);
        let name = question.name.clone();
        msg.add_question(question);

        let rdata = ipv4_to_bytes(Ipv4Addr::new(8, 8, 8, 8));
        let answer = Answer{name, rtype: ResourceType::A, class: ResourceClass::IN, ttl: 60, rdlength: 4, rdata};
        msg.add_answer(answer);
    }

    let response = msg.to_bytes();

    socket
        .send_to(&response, source)
        .expect("Failed to send response");
}

fn ipv4_to_bytes(ip: Ipv4Addr) -> Vec<u8> {
    let octets = ip.octets();
    octets.to_vec()
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
