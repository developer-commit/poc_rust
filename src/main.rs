mod poc;

mod ntdll;
mod helper;
mod exploit;

fn main() {
    poc::poc_2022_37969::run_poc();
}