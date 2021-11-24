use crate::{Authenticator, Result};

use apdu_dispatch::{app::App, command, Command, response};
use trussed::client;

#[cfg(feature = "apdu-dispatch")]
impl<T> App<{command::SIZE}, {response::SIZE}> for Authenticator<T, {command::SIZE}>
where
    T: client::Client + client::Ed255 + client::Tdes
{
    fn select(&mut self, apdu: &Command, reply: &mut response::Data) -> Result {
        self.select(apdu, reply)
    }

    fn deselect(&mut self) { self.deselect() }

    fn call(&mut self, _: iso7816::Interface, apdu: &Command, reply: &mut response::Data) -> Result {
        self.respond(apdu, reply)
    }
}
