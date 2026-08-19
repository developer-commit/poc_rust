mod poc;

mod ntdll;
mod helper;
mod exploit;

fn main() {
    poc::poc_2025_60719::run_poc();
}