use otp::totp::TOTP;

fn main() {
    let secret = vec![
        49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
    ];
    let secret_ascii = "12345678901234567890".to_owned();
    let secret_hex = "3132333435363738393031323334353637383930".to_owned();

    let mut totp = TOTP::new();

    let code = totp.ascii_secret(&secret_ascii).generate();

    println!("{}", code);
}
