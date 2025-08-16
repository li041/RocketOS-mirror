use crate::cmd::*;
use crate::reg::*;
use crate::sd_reg::*;
use crate::CountDown;
use log::{debug, error};

use lego_device::{read_reg, write_reg};

use super::err::*;

pub(super) struct MmcOperate {
    sdio_base: usize,
    get_macros: fn() -> usize,
}

impl MmcOperate {
    pub const fn new(sdio_base: usize, get_macros: fn() -> usize) -> Self {
        Self {
            sdio_base,
            get_macros,
        }
    }
    fn wait_for_cmd_line(&self) -> Result<(), Timeout> {
        if !self.wait_for(0xFF, || {
            read_reg::<u32>(self.sdio_base, REG_CMD) & CmdMask::start_cmd.bits() == 0
        }) {
            Err(Timeout::WaitCmdLine)
        } else {
            Ok(())
        }
    }

    fn wait_for_data_line(&self) -> Result<(), Timeout> {
        if self.wait_for(DATA_TMOUT_DEFUALT, || {
            read_reg::<u32>(self.sdio_base, REG_STATUS) & StatusMask::data_busy.bits() == 0
        }) {
            Ok(())
        } else {
            Err(Timeout::WaitDataLine)
        }
    }

    fn wait_for_cmd_done(&self) -> Result<(), Timeout> {
        if self.wait_for(0xFF, || {
            read_reg::<u32>(self.sdio_base, REG_RINTSTS) & InterruptMask::cmd.bits() != 0
        }) {
            Ok(())
        } else {
            Err(Timeout::WaitCmdDone)
        }
    }

    pub fn wait_reset(&self, mask: u32) -> Result<(), Timeout> {
        if self.wait_for(10, || read_reg::<u32>(self.sdio_base, REG_CTRL) & mask == 0) {
            Ok(())
        } else {
            Err(Timeout::WaitReset)
        }
    }

    pub fn send_cmd(&self, cmd: Command) -> Result<Response, CardError> {
        self.wait_for_cmd_line()?;
        write_reg(self.sdio_base, REG_RINTSTS, InterruptMask::all().bits());

        if cmd.data_exp() {
            self.wait_for_data_line()?;
        }
        write_reg(self.sdio_base, REG_CMDARG, cmd.arg());
        write_reg(self.sdio_base, REG_CMD, cmd.cmd());
        self.wait_for_cmd_done()?;
        let resp = if cmd.resp_exp() {
            let mask: u32 = read_reg(self.sdio_base, REG_RINTSTS);
            if mask & InterruptMask::rto.bits() != 0 {
                write_reg(self.sdio_base, REG_RINTSTS, mask);
                error!(
                    "Response Timeout, mask: {:?}",
                    InterruptMask::from_bits(mask).unwrap()
                );
                return Err(Interrupt::ResponseTimeout.into());
            } else if mask & InterruptMask::re.bits() != 0 {
                write_reg(self.sdio_base, REG_RINTSTS, mask);
                error!(
                    "Response Error, mask : {:?}",
                    InterruptMask::from_bits(mask).unwrap()
                );
                return Err(Interrupt::ResponseErr.into());
            } else if mask & InterruptMask::rcrc.bits() != 0 {
                error!(
                    "Response CRC Error, mask: {:?}",
                    InterruptMask::from_bits(mask).unwrap()
                );
                return Err(Interrupt::ResponseCrc.into());
            }
            if cmd.resp_lang() {
                let resp0 = read_reg(self.sdio_base, REG_RESP0);
                let resp1 = read_reg(self.sdio_base, REG_RESP1);
                let resp2 = read_reg(self.sdio_base, REG_RESP2);
                let resp3 = read_reg(self.sdio_base, REG_RESP3);
                Response::R136((resp0, resp1, resp2, resp3))
            } else {
                Response::R48(read_reg::<u32>(self.sdio_base, REG_RESP0))
            }
        } else {
            Response::Rz
        };
        if cmd.data_exp() {
            self.wait_reset(ControlMask::fifo_reset.bits())?;
        }
        self.delay_macros(100);
        Ok(resp)
    }

    pub fn read_data(&self, buf: &mut [u8], blk: u32, blk_sz: u32) -> Result<(), CardError> {
        write_reg::<u32>(self.sdio_base, REG_BLKSIZ, blk_sz);
        write_reg::<u32>(self.sdio_base, REG_BYTCNT, blk_sz * blk);
        let size = (blk * blk_sz) as usize;
        let mut offset = 0;
        let timer = CountDown::new(DATA_TMOUT_DEFUALT, self.get_macros);
        loop {
            let mask = read_reg::<u32>(self.sdio_base, REG_RINTSTS);
            if offset == size && mask & InterruptMask::dto.bits() != 0 {
                break;
            }
            Interrupt::check(mask)?;
            self.delay_macros(10);
            if timer.timeout() {
                return Err(CardError::DataTransferTimeout);
            }
            if mask & (InterruptMask::rxdr | InterruptMask::dto).bits() != 0 {
                while (read_reg::<u32>(self.sdio_base, REG_STATUS) >> 17) & 0x1FFF != 0 {
                    buf[offset] = read_reg::<u8>(self.sdio_base, REG_DATA + offset);
                    offset += 1;
                }
                write_reg::<u32>(self.sdio_base, REG_RINTSTS, InterruptMask::rxdr.bits());
            }
        }
        write_reg::<u32>(
            self.sdio_base,
            REG_RINTSTS,
            read_reg::<u32>(self.sdio_base, REG_RINTSTS),
        );
        Ok(())
    }

    pub fn write_data(&self, buf: &[u8], blk: u32, blk_sz: u32) -> Result<(), CardError> {
        write_reg::<u32>(self.sdio_base, REG_BLKSIZ, blk_sz);
        write_reg::<u32>(self.sdio_base, REG_BYTCNT, blk * blk_sz);
        let timer = CountDown::new(DATA_TMOUT_DEFUALT, self.get_macros);
        loop {
            let mask = read_reg::<u32>(self.sdio_base, REG_RINTSTS);
            if InterruptMask::dto.bits() & mask != 0 {
                break;
            }
            Interrupt::check(mask)?;
            self.delay_macros(10);
            if timer.timeout() {
                return Err(CardError::DataTransferTimeout);
            }
            if mask & InterruptMask::txdr.bits() != 0 {
                for (offset, byte) in buf.iter().enumerate() {
                    write_reg::<u8>(self.sdio_base, REG_DATA + offset, *byte);
                }
                write_reg::<u32>(self.sdio_base, REG_RINTSTS, InterruptMask::txdr.bits());
            }
        }
        write_reg::<u32>(
            self.sdio_base,
            REG_RINTSTS,
            read_reg::<u32>(self.sdio_base, REG_RINTSTS),
        );
        Ok(())
    }

    pub fn reset_clock(&self, ena: u32, div: u32) -> Result<(), Timeout> {
        self.wait_for_cmd_line()?;
        write_reg::<u32>(self.sdio_base, REG_CLKENA, 0);
        write_reg::<u32>(self.sdio_base, REG_CLKDIV, div);
        let cmd = up_clk();
        write_reg::<u32>(self.sdio_base, REG_CMDARG, cmd.arg());
        write_reg::<u32>(self.sdio_base, REG_CMD, cmd.cmd());
        if ena == 0 {
            return Ok(());
        }
        self.wait_for_cmd_line()?;
        write_reg::<u32>(self.sdio_base, REG_CMD, cmd.cmd());
        self.wait_for_cmd_line()?;
        write_reg::<u32>(self.sdio_base, REG_CLKENA, ena);
        write_reg::<u32>(self.sdio_base, REG_CMDARG, 0);
        write_reg::<u32>(self.sdio_base, REG_CMD, cmd.cmd());
        debug!("reset clock");
        Ok(())
    }

    pub fn check_version(&self) -> Result<Cic, CardError> {
        self.delay_milli(10);
        let cmd = send_if_cond(1, 0xAA);
        let cic = self.send_cmd(cmd)?.cic();
        if cic.voltage_accepted() == 1 && cic.pattern() == 0xAA {
            debug!("sd vision 2.0");
            Ok(cic)
        } else {
            Err(CardError::VoltagePattern)
        }
    }

    pub fn check_v18_sdhc(&self) -> Result<Ocr, CardError> {
        self.delay_milli(10);
        let ocr = loop {
            let cmd = app_cmd(0);
            let status = self.send_cmd(cmd)?.card_status();
            debug!("{status:?}");
            let cmd = sd_send_op_cond(true, true);
            let ocr = self.send_cmd(cmd)?.ocr();
            if !ocr.is_busy() {
                if ocr.high_capacity() {
                    debug!("card is high capacity!");
                }
                if ocr.v18_allowed() {
                    debug!("card can switch to 1.8 voltage!");
                }
                break ocr;
            }
            self.delay_milli(2);
        };
        Ok(ocr)
    }

    pub fn check_rca(&self) -> Result<Rca, CardError> {
        self.delay_milli(10);
        let cmd = send_relative_address();
        let rca = self.send_cmd(cmd)?.rca();
        debug!("{:?}", rca);
        Ok(rca)
    }

    pub fn check_cid(&self) -> Result<Cid, CardError> {
        self.delay_milli(10);
        let cmd = all_send_cid();
        let cid = self.send_cmd(cmd)?.cid();
        debug!("{:?}", cid);
        Ok(cid)
    }

    pub fn check_csd(&self, rca: Rca) -> Result<Csd, CardError> {
        self.delay_milli(10);
        let cmd = send_csd(rca.address());
        let csd = self.send_cmd(cmd)?.csd();
        debug!("{:?}", csd);
        Ok(csd)
    }

    pub fn sel_card(&self, rca: Rca) -> Result<(), CardError> {
        self.delay_milli(10);
        let cmd = select_card(rca.address());
        let status = self.send_cmd(cmd)?.card_status();
        debug!("{:?}", status);
        Ok(())
    }

    pub fn function_switch(&self, arg: u32) -> Result<(), CardError> {
        self.delay_milli(10);
        let cmd = switch_function(arg);
        let status = self.send_cmd(cmd)?.card_status();
        debug!("{:?}", status);
        Ok(())
    }

    pub fn set_bus(&self, rca: Rca) -> Result<(), CardError> {
        self.delay_milli(10);
        self.send_cmd(app_cmd(rca.address()))?;
        let status = self.send_cmd(set_bus_width(2))?.card_status();
        debug!("{:?}", status);
        Ok(())
    }

    pub fn stop_transmission_ops(&self) -> Result<(), CardError> {
        let cmd = stop_transmission();
        loop {
            self.wait_for_cmd_line()?;
            write_reg::<u32>(self.sdio_base, REG_RINTSTS, InterruptMask::all().bits());
            write_reg::<u32>(self.sdio_base, REG_CMDARG, cmd.arg());
            write_reg::<u32>(self.sdio_base, REG_CMD, cmd.cmd());
            if read_reg::<u32>(self.sdio_base, REG_RINTSTS) & InterruptMask::hle.bits() == 0 {
                debug!("send {:?}", CmdMask::from_bits(cmd.cmd()).unwrap());
                break;
            }
        }
        let status = Response::R48(read_reg(self.sdio_base, REG_RESP0)).card_status();
        debug!("{status:?}");
        self.wait_for_cmd_done()?;
        Ok(())
    }

    fn wait_for<F: FnMut() -> bool>(&self, millis: usize, mut f: F) -> bool {
        let count_down = CountDown::new(millis, self.get_macros);
        loop {
            if count_down.timeout() {
                return false;
            }
            if f() {
                break;
            }
        }
        true
    }

    fn delay_milli(&self, millis: usize) {
        self.delay_macros(millis * 1000);
    }

    fn delay_macros(&self, macros: usize) {
        let deadline = macros + (self.get_macros)();
        while (self.get_macros)() < deadline {
            core::hint::spin_loop();
        }
    }
}
