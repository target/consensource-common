// Copyright 2018 Cargill Incorporated
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contains functions which assist with error management

use sawtooth_sdk::signing;
use std::borrow::Borrow;
use std::error::Error as StdError;

#[derive(Debug)]
pub enum ConsenSourceError {
    /// The user has provided invalid inputs; the string by this error
    /// is appropriate for display to the user without additional context
    UserError(String),
    IoError(std::io::Error),
    SigningError(signing::Error),
    ProtobufError(protobuf::ProtobufError),
    InvalidTransactionError(String),
    InvalidInputError(String),
}

impl StdError for ConsenSourceError {
    fn cause(&self) -> Option<&dyn StdError> {
        match *self {
            ConsenSourceError::UserError(ref _s) => None,
            ConsenSourceError::IoError(ref err) => Some(err.borrow()),
            ConsenSourceError::SigningError(ref err) => Some(err.borrow()),
            ConsenSourceError::ProtobufError(ref err) => Some(err.borrow()),
            ConsenSourceError::InvalidTransactionError(ref _s) => None,
            ConsenSourceError::InvalidInputError(ref _s) => None,
        }
    }
}

impl std::fmt::Display for ConsenSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            ConsenSourceError::UserError(ref s) => write!(f, "Error: {}", s),
            ConsenSourceError::IoError(ref err) => write!(f, "IoError: {}", err),
            ConsenSourceError::SigningError(ref err) => {
                write!(f, "SigningError: {}", err.to_string())
            }
            ConsenSourceError::ProtobufError(ref err) => {
                write!(f, "ProtobufError: {}", err.to_string())
            }
            ConsenSourceError::InvalidTransactionError(ref s) => {
                write!(f, "InvalidTransactionError: {}", s)
            }
            ConsenSourceError::InvalidInputError(ref s) => write!(f, "InvalidInput: {}", s),
        }
    }
}

impl From<std::io::Error> for ConsenSourceError {
    fn from(e: std::io::Error) -> Self {
        ConsenSourceError::IoError(e)
    }
}

impl From<protobuf::ProtobufError> for ConsenSourceError {
    fn from(e: protobuf::ProtobufError) -> Self {
        ConsenSourceError::ProtobufError(e)
    }
}

impl From<signing::Error> for ConsenSourceError {
    fn from(e: signing::Error) -> Self {
        ConsenSourceError::SigningError(e)
    }
}
