import "reflect-metadata"
import { DbOpts } from './config'
import { DataSource } from "typeorm"
import { EmissionsFactor } from "./models/emissionsFactor"
import { UtilityLookupItem } from "./models/utilityLookupItem"
import { Wallet } from "./models/wallet"


export const initDb = async (opts: DbOpts) => {

  const AppDataSource = new DataSource({
    type: "postgres",
    host: opts.dbHost,
    port: opts.dbPort,
    username: opts.dbUser,
    password: opts.dbPassword,
    database: opts.dbName,
    entities: [EmissionsFactor, UtilityLookupItem, Wallet],
    synchronize: true,
    logging: false,
  })

  // to initialize initial connection with the database, register all entities
  // and "synchronize" database schema, call "initialize()" method of a newly created database
  // once in your application bootstrap
  return await AppDataSource.initialize()
}

