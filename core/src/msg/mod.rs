mod codec;
mod types;

pub use codec::{
    max_bytes_for_type, read_msg, read_msg_limited, read_msg_limited_timeout,
    read_msg_with_limits, write_msg, MessageReadError, MessageWriteError,
};
pub use types::*;
