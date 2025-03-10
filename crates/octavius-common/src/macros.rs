#[macro_export]
macro_rules! next_enum_of {
    ($vec: expr, $variant: pat => $map_fn: expr) => {
        $vec.iter()
            .filter_map(|x| if let $variant = x { Some($map_fn) } else { None })
            .next()
    };
}

#[macro_export]
macro_rules! type_enum {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident: $from:ident($T:ty) {
            $(
                $(#[$inner:ident $($args:tt)*])*
                $value_name:ident = $value:expr
            ),*
        }
    ) => {
        $(#[$outer])*
        $vis enum $name {
            $(
                $(#[$inner $($args)*])*
                $value_name,
            )*
            Unknown($T)
        }

        impl crate::BGPElement for $name {
            fn unpack(input: &[u8]) -> nom::IResult<&[u8], Self> where Self: Sized {
                let (input, value) = nom::number::complete::$from(input)?;
                Ok((input, match value {
                    $(
                        $value => Self::$value_name,
                    )*
                    _ => Self::Unknown(value)
                }))
            }

            fn pack(&self) -> alloc::vec::Vec<u8> {
                let mut buffer = alloc::vec::Vec::new();
                buffer.extend_from_slice(&match self {
                    $(
                        Self::$value_name => $value,
                    )*
                    Self::Unknown(value) => *value
                }.to_be_bytes());
                buffer
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $(
                        Self::$value_name => write!(formatter, stringify!($name)),
                    )*
                    Self::Unknown(value) => write!(formatter, "Unknown ({})", value)
                }
            }
        }

        impl From<$T> for $name {
            fn from(value: $T) -> Self {
                match value {
                    $(
                        $value => Self::$value_name,
                    )*
                    _ => Self::Unknown(value)
                }
            }
        }

        impl From<$name> for $T {
            fn from(value: $name) -> Self {
                match value {
                    $(
                        $name::$value_name => $value,
                    )*
                    $name::Unknown(value) => value
                }
            }
        }
    };
}
