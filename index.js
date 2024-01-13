import express from 'express'
import pg from 'pg'
import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'
import { v4 } from 'uuid'
import env from 'env-var'
import 'dotenv/config'
import request from 'request'

const PostgresUrl = env.get('POSTGRES_URL').required(true).asString()
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
  } else {
    throw new Error('Invalid response from certification endpoint')
  }
}

const pool = new pg.Pool({
  connectionString: PostgresUrl
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
  const sessionId = v4()

  return {
    token: generateAccessToken(user, sessionId),
    refreshToken: generateRefreshToken(user, sessionId),
    scope: null
  }
}

const generateRefreshToken = (user, sessionId) => {
  return jwt.sign(
    {
      userId: user.id,
      scopes: ['REFRESH_TOKEN'],
      sessionId,
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

const generateAccessToken = (user, sessionId) => {
  return jwt.sign(
    {
      userId: user.id,
      scopes: [user.authority],
      sessionId,
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

      const email = decodedJwt.payload.email
      if (email === undefined) {
        return res.status(403).send('Authentication failed')
      }

      res.json(await generateTokens(email))
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
    console.log(e)
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
