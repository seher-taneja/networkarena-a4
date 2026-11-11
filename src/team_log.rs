//! The team's log, in a run where the harness forwards: what the program
//! chose to write down, on the one switch it named for it. The detector
//! reads this and nothing else.
//!
//! A controller names its switch the logging switch with
//! `ControllerAction::NameLoggingSwitch`. The first switch to ask gets it
//! for the rest of the run. Every switch's first timer fires at time zero
//! in switch-id order, so among those asking then the lowest id wins. Only the logging switch's
//! `ControllerAction::LogWrite`s count, and each is kept whole or lost
//! whole: it is lost if it would take the log past its cap. The log is the
//! kept writes' bytes back to back, with nothing added. Framing and
//! timestamps are the program's to write.

use crate::types::SwitchId;

/// Why a write was not kept, as `LogEvent::TeamLogRefused` records it.
pub const REFUSED_NOT_LOGGING_SWITCH: u8 = 0;
pub const REFUSED_FULL: u8 = 1;

#[derive(Debug, Clone, Default)]
pub struct TeamLog {
    pub cap_bytes: usize,
    /// The logging switch, once one is named.
    pub switch: Option<SwitchId>,
    pub bytes: Vec<u8>,
}

impl TeamLog {
    pub fn new(cap_bytes: usize) -> Self {
        Self { cap_bytes, ..Default::default() }
    }

    /// `switch` asks to be the logging switch. True if it is, now or
    /// already.
    pub fn name(&mut self, switch: SwitchId) -> bool {
        *self.switch.get_or_insert(switch) == switch
    }

    /// `switch` writes `bytes`. `Ok` if kept, else why not.
    pub fn write(&mut self, switch: SwitchId, bytes: &[u8]) -> Result<(), u8> {
        if self.switch != Some(switch) {
            return Err(REFUSED_NOT_LOGGING_SWITCH);
        }
        if self.bytes.len() + bytes.len() > self.cap_bytes {
            return Err(REFUSED_FULL);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_switch_to_ask_logs_and_writes_are_whole_or_lost() {
        let (a, b) = (SwitchId::new(3), SwitchId::new(1));
        let mut log = TeamLog::new(10);
        assert_eq!(log.write(a, b"x"), Err(REFUSED_NOT_LOGGING_SWITCH), "nobody named yet");
        assert!(log.name(a));
        assert!(!log.name(b));
        assert!(log.name(a), "asking again changes nothing");
        assert_eq!(log.write(b, b"x"), Err(REFUSED_NOT_LOGGING_SWITCH));
        assert_eq!(log.write(a, b"123456"), Ok(()));
        assert_eq!(log.write(a, b"78901"), Err(REFUSED_FULL), "one byte over: all of it lost");
        assert_eq!(log.write(a, b"7890"), Ok(()), "a write that fits still goes in");
        assert_eq!(log.bytes, b"1234567890");
        assert_eq!(log.write(a, b""), Ok(()));
        assert_eq!(log.write(a, b"!"), Err(REFUSED_FULL));
    }
}
