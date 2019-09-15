use std::error;
use std::fmt;
use libusb::Error as usbError;
use std::io::Error as ioError;

#[derive(Debug)]
pub enum YubicoError {
    IOError(ioError),
    UsbError(usbError),
    CommandNotSupported,
    DeviceNotFound,
    OpenDeviceError,
    CanNotWriteToDevice,
    WrongCRC,
    ConfigNotWritten,
}

impl fmt::Display for YubicoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            YubicoError::IOError(ref err) => write!(f, "IO error: {}", err),
            YubicoError::UsbError(ref err) => write!(f, "USB  error: {}", err),
            YubicoError::DeviceNotFound => write!(f, "Device not found"),
            YubicoError::OpenDeviceError => write!(f, "Can not open device"),
            YubicoError::CommandNotSupported => write!(f, "Command Not Supported"),
            YubicoError::WrongCRC => write!(f, "Wrong CRC"),            
            YubicoError::CanNotWriteToDevice => write!(f, "Can not write to Device"),
            YubicoError::ConfigNotWritten => write!(f, "Configuration has failed"),
        }
    }
}

impl error::Error for YubicoError {
    fn description(&self) -> &str {
        match *self {
            YubicoError::IOError(ref err) => err.description(),
            YubicoError::UsbError(ref err) => err.description(),
            YubicoError::DeviceNotFound => "Yubikey device not found",
            YubicoError::OpenDeviceError => "Can not open device",
            YubicoError::CommandNotSupported => "Command Not Supported",
            YubicoError::WrongCRC => "Wrong CRC",            
            YubicoError::CanNotWriteToDevice => "Can not write to Device", 
            YubicoError::ConfigNotWritten => "Can configure the Device",
        }
    }

    fn cause(&self) -> Option<& dyn error::Error> {
        match *self {
            YubicoError::UsbError(ref err) => Some(err),                    
            _ => None
        }
    }
}

impl From<ioError> for YubicoError {
    fn from(err: ioError) -> YubicoError {
        YubicoError::IOError(err)
    }
}

impl From<usbError> for YubicoError {
    fn from(err: usbError) -> YubicoError {
        YubicoError::UsbError(err)
    }
}