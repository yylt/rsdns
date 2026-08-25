use slog::Drain;
use time::OffsetDateTime;

pub struct AsyncGuard {
    _scope_guard: slog_scope::GlobalLoggerGuard,
    _async_guard: slog_async::AsyncGuard,
}

pub fn init(level: log::LevelFilter) -> AsyncGuard {
    let slog_level = match level {
        log::LevelFilter::Off => slog::Level::Critical,
        log::LevelFilter::Error => slog::Level::Error,
        log::LevelFilter::Warn => slog::Level::Warning,
        log::LevelFilter::Info => slog::Level::Info,
        log::LevelFilter::Debug => slog::Level::Debug,
        log::LevelFilter::Trace => slog::Level::Trace,
    };

    let drain = CompactFormat { max_level: slog_level };
    let (drain, async_guard) = slog_async::Async::new(drain)
        .chan_size(16384)
        .thread_name("slog-io".into())
        .build_with_guard();

    let logger = slog::Logger::root(drain.fuse(), slog::o!());
    let scope_guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init_with_level(match level {
        log::LevelFilter::Off => log::Level::Error,
        log::LevelFilter::Error => log::Level::Error,
        log::LevelFilter::Warn => log::Level::Warn,
        log::LevelFilter::Info => log::Level::Info,
        log::LevelFilter::Debug => log::Level::Debug,
        log::LevelFilter::Trace => log::Level::Trace,
    })
    .expect("slog-stdlog init failed");

    AsyncGuard {
        _scope_guard: scope_guard,
        _async_guard: async_guard,
    }
}

struct CompactFormat {
    max_level: slog::Level,
}

impl Drain for CompactFormat {
    type Ok = ();
    type Err = slog::Never;

    fn log(&self, record: &slog::Record, _values: &slog::OwnedKVList) -> Result<Self::Ok, Self::Err> {
        use std::io::Write;

        if !record.level().is_at_least(self.max_level) {
            return Ok(());
        }

        let level_char = match record.level() {
            slog::Level::Critical | slog::Level::Error => 'E',
            slog::Level::Warning => 'W',
            slog::Level::Info => 'I',
            slog::Level::Debug => 'D',
            slog::Level::Trace => 'T',
        };

        let date = {
            match OffsetDateTime::now_local() {
                Ok(now) => format!("{:02}{:02}", u8::from(now.month()), now.day()),
                Err(_) => {
                    let now = OffsetDateTime::now_utc();
                    format!("{:02}{:02}", u8::from(now.month()), now.day())
                }
            }
        };

        let target = record.module();
        let function = record.function();
        let source = if !function.is_empty() {
            format!("{}::{}", target, function)
        } else {
            target.to_string()
        };

        let _ = writeln!(std::io::stderr(), "{}{} [{}] {}", level_char, date, source, record.msg());
        Ok(())
    }
}
