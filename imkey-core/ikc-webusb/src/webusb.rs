use bytes::{BufMut, BytesMut};

pub fn webusb_send(apdu: &str, timeout: i32) -> String {
    "".to_string()
}


fn as_u16_be(value: usize) -> BytesMut {
    let mut b = BytesMut::with_capacity(2);
    b.put_u16(value as u16);
    b
}

// 定义常量
const COMMAND_TYPE_MESSAGE: u8 = 0x43 | 0x80;
const COMMAND_TYPE_CANCEL: u8 = 0x51 | 0x80;
const COMMAND_TYPE_ERROR: u8 = 0x7F | 0x80;
const COMMAND_TYPE_KEEPALIVE: u8 = 0x7B | 0x80;

fn make_blocks(apdu: &[u8]) -> Vec<BytesMut> {
    let mut data = BytesMut::with_capacity(2 + apdu.len());//指令长度（2） + 指令原值
    data.put(as_u16_be(apdu.len()));
    data.put(apdu);
    println!("data-->{}", hex::encode(data.clone()));
    let packet_size = 64;
    let block_size = packet_size - 5;
    let nb_blocks = (data.len() + block_size - 1) / block_size;
    println!("nb_blocks-->{}", nb_blocks);
    let mut blocks: Vec<BytesMut> = Vec::with_capacity(nb_blocks);
    let mut data_index = 0;

    for i in 0..nb_blocks {
        let mut head = BytesMut::with_capacity(5);

        if i == 0 {
            if apdu.len() == 2 && apdu == b"\x00\x00" {
                head.put_slice(&[0x00, 0x00, 0x00, 0x00]);
                head.put_u8(COMMAND_TYPE_CANCEL);
                head.resize(64, 0);
                blocks.push(head);
                return blocks;
            }
            head.put_slice(&[0x00, 0x00, 0x00, 0x00]);
            head.put_u8(COMMAND_TYPE_MESSAGE);
            let chunk = &data[data_index..std::cmp::min(data.len(), data_index + block_size)];
            data_index += block_size;

            let mut block = BytesMut::with_capacity(64);
            block.put(head);
            block.put(chunk);
            block.resize(64, 0);
            blocks.push(block);
        } else {
            head.put_slice(&[0x00, 0x00, 0x00, 0x00]);
            head.put_u8((i - 1) as u8);
            let chunk = &data[data_index..std::cmp::min(data.len(), data_index + block_size)];
            data_index += block_size;

            let mut block = BytesMut::with_capacity(64);
            block.put(head);
            block.put(chunk);
            block.resize(64, 0);
            blocks.push(block);
        }

        if data_index >= data.len() {
            break;
        }
    }

    blocks
}

#[cfg(test)]
mod test{
    use super::make_blocks;

    #[test]
    fn test(){
        let result = make_blocks(hex::decode("00A40400001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111122").unwrap().as_slice());
        let result = make_blocks(hex::decode("00A40400001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222").unwrap().as_slice());
        // let result = make_blocks(hex::decode("0000").unwrap().as_slice());
        for val in result {
            println!("-->{}", hex::encode(val));
        }
    }
}