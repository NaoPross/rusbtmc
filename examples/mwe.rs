use rusbtmc;

fn main() {
    if let Ok(instruments) = rusbtmc::instruments() {
        for instr in instruments {
            let desc = match instr.device.device_descriptor() {
                Ok(d) => d,
                Err(e) => {
                    dbg!("failed to get descriptor", e);
                    continue;
                }
            };

            let handle = match instr.device.open() {
                Ok(h) => h,
                Err(e) => {
                    dbg!("failed to get handle", e);
                    continue;
                }
            };

            let prodstr = match handle.read_product_string_ascii(&desc) {
                Ok(s) => s,
                Err(e) => {
                    dbg!("failed to get product string", e);
                    continue;
                }
            };

            dbg!(prodstr);
        }
    }
}
