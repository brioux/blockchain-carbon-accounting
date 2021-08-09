import winston, { Logger } from 'winston';

// every class will create a logger and each method
// will create methodLogger = this.log.child({fnTag : <name>})
export function getClassLogger(logLevel: string, className: string): Logger {
  const log = winston.createLogger({
    level: logLevel,
    format: winston.format.combine(
      winston.format.splat(),
      winston.format.timestamp(),
      winston.format.label({ label: 'SECURE-FABRIC' }),
      winston.format.colorize({
        message: true,
        colors: {
          debug: 'cyan',
          info: 'green',
          warn: 'yellow',
          error: 'red',
        },
      }),
      winston.format.printf((info) => {
        return `[ ${info.label} ] [ ${info.level.toUpperCase()} ] ${info.class}::${info.fnTag}() : ${info.message}`;
      })
    ),
    transports: [new winston.transports.Console()],
  });
  return log.child({ class: className });
}

export function getMethodLogger(classLogger: Logger, fnTag: string): Logger {
  return classLogger.child({ fnTag: fnTag });
}

export interface Options {
  logLevel: 'debug' | 'info' | 'error';
}
