'use strict'

import express from 'express'
import pg from 'pg'
import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'
import { v4 } from 'uuid'
import env from 'env-var'
import 'dotenv/config'
import request from 'request'

const PostgresUsername = env
  .get('POSTGRES_USER')
  .required(true)
  .default('postgres')
  .asString()
const PostgresPassword = env.get('POSTGRES_SECRET').required(true).asString()
const PostgresHost = env.get('POSTGRES_HOST').required(true).asString()
const PostgresPort = env
  .get('POSTGRES_PORT')
  .required(true)
  .default('5432')
  .asPortNumber()
const PostgresDatabase = env
  .get('POSTGRES_DATABASE')
  .required(true)
  .default('thingsboard')
  .asString()
const TokenSigningKey = env.get('TOKEN_SIGNING_KEY').required(true).asString()
const AccessTokenExpiration = env
  .get('ACCESS_TOKEN_EXPIRATION')
  .required(true)
  .default('9000s')
  .asString()
const RefreshTokenExpiration = env
  .get('REFRESH_TOKEN_EXPIRATION')
  .required(true)
  .default('604800s')
  .asString()
const CertsEndpoint = env
  .get('OAUTH2_CERTS_ENDPOINT')
  .required(true)
  .asString()
const ThingsboardAuthUrl = env
  .get('THINGSBOARD_AUTH_URL')
  .required(true)
  .asString()

const fetchCerts = async () => {
  const response = await fetch(CertsEndpoint)
  if (response.ok) {
    return response.json()
  }
}

const pool = new pg.Pool({
  user: PostgresUsername,
  password: PostgresPassword,
  host: PostgresHost,
  database: PostgresDatabase,
  port: PostgresPort
})
const app = express()
const certs = await fetchCerts()

app.use(express.json())

const generateTokens = async (email) => {
  const users = await pool.query('SELECT * FROM tb_user WHERE email = $1', [
    email
  ])
  if (users.rowCount !== 1) {
    throw new Error('User not found')
  }

  const [user] = users.rows

  return {
    token: generateAccessToken(user),
    refreshToken: generateRefreshToken(user),
    scope: null
  }
}

const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      scopes: ['REFRESH_TOKEN'],
      isPublic: false
    },
    TokenSigningKey,
    {
      algorithm: 'HS512',
      subject: user.email,
      issuer: 'thingsboard.io',
      expiresIn: RefreshTokenExpiration
    }
  )
}

const generateAccessToken = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      scopes: [user.authority],
      enabled: true,
      isPublic: false,
      tenantId: user.tenant_id,
      customerId: user.customer_id
    },
    TokenSigningKey,
    {
      algorithm: 'HS512',
      subject: user.email,
      issuer: 'thingsboard.io',
      expiresIn: AccessTokenExpiration
    }
  )
}

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { username, password: accessToken } = req.body
    if (username === 'oauth2-token') {
      const decodedJwt = jwt.decode(accessToken, {
        complete: true
      })

      const jwk = certs.keys.find((key) => key.kid === decodedJwt.header.kid)
      if (jwk === null) {
        throw new Error('jwk not found')
      }

      jwt.verify(accessToken, jwkToPem(jwk))

      res.json(await generateTokens(decodedJwt.payload.email))
    } else {
      request
        .post({
          url: ThingsboardAuthUrl,
          body: req.body,
          json: true
        })
        .pipe(res)
    }
  } catch (e) {
    return res.status(401).json({
      status: 401,
      message: 'Invalid username or password',
      errorCode: 10,
      timestamp: new Date()
    })
  }
})

app.get('/', (req, res) => {
  res.send('OK')
})

app.listen(3000)
