use digest::{
    FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, Update,
    common::BlockSizeUser,
    consts::{U32, U64},
};
use embassy_rp::pac::SHA256;

#[derive(Clone, Default)]
pub struct Sha2 {
    bits_written: u32,
    word_buf: [u8; 4],
    word_pos: usize,
}

impl BlockSizeUser for Sha2 {
    type BlockSize = U64;
}

impl HashMarker for Sha2 {}

impl OutputSizeUser for Sha2 {
    type OutputSize = U32;
}

impl Sha2 {
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

    fn output_hash(&mut self, out: &mut digest::Output<Self>) {
        let original_msg_bit_len = (self.bits_written + self.word_pos as u32 * 8) as u64;
        // Append the null byte denoting the end of the message
        self.update(&[0x80]);
        // Padding until the 512 - 64bits is met
        while (self.bits_written + self.word_pos as u32 * 8) % 512 != 448 {
            self.update(&[0x00]);
        }
        // Appending the length
        let len_bytes = original_msg_bit_len.to_be_bytes();
        self.update(&len_bytes);
        // Wait for the hardware to compute the hash
        while !SHA256.csr().read().sum_vld() {}
        // Retrieve the hash
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

impl Update for Sha2 {
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

impl FixedOutput for Sha2 {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        // info!("[HW_SHA] finalize_into()");
        self.output_hash(out);
    }
}

impl Reset for Sha2 {
    fn reset(&mut self) {
        SHA256.csr().write(|w| {
            w.set_start(true);
            w.set_bswap(true);
        });
        self.bits_written = 0;
        self.word_pos = 0;
        self.word_buf = [0u8; 4];
    }
}

impl FixedOutputReset for Sha2 {
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        self.output_hash(out);
    }
}
