pub struct CountDown {
    deadline: usize,
    get_macros: fn() -> usize,
}

impl CountDown {
    pub fn new(millis: usize, get_macros: fn() -> usize) -> Self {
        let now = get_macros();
        Self {
            deadline: millis * 1000 + now,
            get_macros,
        }
    }

    pub fn timeout(&self) -> bool {
        (self.get_macros)() > self.deadline
    }
}
