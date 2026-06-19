use defmt::info;
use digest::{
    FixedOutput, HashMarker, OutputSizeUser, Reset, Update,
    common::BlockSizeUser,
    consts::{U32, U64},
};
use embassy_rp::pac::SHA256;

#[derive(Clone, Default)]
pub struct RpSha2 {
    bits_written: u32,
    word_buf: [u8; 4],
    word_pos: usize,
}

impl BlockSizeUser for RpSha2 {
    type BlockSize = U64;
}

impl HashMarker for RpSha2 {}

impl OutputSizeUser for RpSha2 {
    type OutputSize = U32;
}

impl RpSha2 {
    pub fn new() -> Self {
        let mut s = Self {
            bits_written: 0,
            word_buf: [0u8; 4],
            word_pos: 0,
        };
        s.reset();
        s
    }

    fn write_word(&mut self, word: [u8; 4]) {
        while !SHA256.csr().read().wdata_rdy() {
            // info!("Waiting for write ready");
        }
        let word = u32::from_ne_bytes(word);
        SHA256.wdata().write_value(word);
        self.bits_written += 32;
        self.word_buf.fill(0);
        self.word_pos = 0;
    }
}

impl Update for RpSha2 {
    fn update(&mut self, data: &[u8]) {
        // info!("[HW_SHA] update()");
        if self.word_pos == 4 {
            self.write_word(self.word_buf);
        }
        for byte in data {
            self.word_buf[self.word_pos] = *byte;
            self.word_pos += 1;
            if self.word_pos == 4 {
                self.write_word(self.word_buf);
            }
        }
    }
}

impl FixedOutput for RpSha2 {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        // info!("[HW_SHA] finalize_into()");

        // NOTE. There may be a couple of bits in the buffer
        let original_message_bit_length = (self.bits_written + self.word_pos as u32 * 8) as u64;
        /*
        info!(
            "Original Message Bit Length: {}",
            original_message_bit_length
        );
        */
        let original_message_length_bytes = original_message_bit_length.to_be_bytes();

        let end_of_msg = [0x80];
        self.update(&end_of_msg);
        if self.word_pos > 0 {
            // this will contain the last block with some zeros at the end.
            self.write_word(self.word_buf);
        }
        let bits = 512 - self.bits_written % 512;
        // info!("Bits until next 512bit window: {}", bits);
        let zero_words_required = (bits - 64) / 32;
        //info!("Zero words required: {}", zero_words_required);
        for _ in 0..zero_words_required {
            self.write_word([0u8; 4]);
        }
        //info!("Bits written: {}", self.bits_written);

        // Writing out the message length
        for chunk in original_message_length_bytes.chunks(4) {
            //info!("Writing message length");
            self.write_word(chunk.try_into().unwrap());
        }
        //info!("Total Bits written: {}", self.bits_written);
        let _should_be_zero = self.bits_written % 512;
        //info!("Should be zero: {}", should_be_zero);

        let mut n = 0;
        loop {
            let valid = SHA256.csr().read().sum_vld();
            //info!("Waiting: {}", valid);
            if valid {
                break;
            }
            n += 1;
            if n > 5 {
                //info!("Timeout");
                break;
            }
        }
        let arr = [
            SHA256.sum0().read(),
            SHA256.sum1().read(),
            SHA256.sum2().read(),
            SHA256.sum3().read(),
            SHA256.sum4().read(),
            SHA256.sum5().read(),
            SHA256.sum6().read(),
            SHA256.sum7().read(),
        ];
        for (i, a) in arr.iter().enumerate() {
            let bytes = a.to_be_bytes();
            let left = i * 4;
            let right = (i + 1) * 4;
            out[left..right].copy_from_slice(bytes.as_slice());
        }
        self.reset();
    }
}

impl Reset for RpSha2 {
    fn reset(&mut self) {
        //info!("[HW_SHA] reset()");
        SHA256.csr().write(|w| {
            w.set_start(true);
            w.set_bswap(true);
        });
    }
}
