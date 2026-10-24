import { FILEBASE_API_URL } from './constants.ts'
import type { RequiredArgs } from './types.ts'
import * as crypto from 'node:crypto'

import { createHash, createHmac } from 'node:crypto'
import type { AwsCredentialIdentity, HttpRequest as IHttpRequest, QueryParameterBag } from '@smithy/types'

export const parseUrl = (
  url: string | URL,
): Pick<IHttpRequest, 'hostname' | 'port' | 'protocol' | 'path' | 'query'> => {
  if (typeof url === 'string') {
    return parseUrl(new URL(url))
  }
  const { hostname, pathname, port, protocol } = url as URL

  return {
    hostname,
    port: port ? parseInt(port) : undefined,
    protocol,
    path: pathname,
    query: undefined,
  }
}

export type RequestOptions = {
  host: string
  region: string
  service: string
  method: string
  path: string
  headers: Record<string, string | number>
  key?: string
}

export const generateFilebaseRequestOptions = (
  token: string,
  requestOptions: RequestOptions,
) => {
  const [accessKeyId, secretAccessKey] = atob(token).split(':')
  if (!accessKeyId || !secretAccessKey) {
    throw new Error('Missing access key ID and secret access key')
  }

  const now = new Date()
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '')
  const dateStamp = amzDate.slice(0, 8)

  // Payload hash (empty string for PUT with no body)
  const payloadHash = crypto.createHash('sha256').update('').digest('hex')

  // Canonical request
  const canonicalHeaders = `content-length:${
    requestOptions.headers['Content-Length']
  }\nhost:${requestOptions.host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`
  const signedHeaders = 'content-length;host;x-amz-content-sha256;x-amz-date'
  const canonicalRequest = [
    requestOptions.method,
    requestOptions.path,
    '', // query string
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n')

  const hashedCanonicalRequest = crypto.createHash('sha256').update(canonicalRequest).digest('hex')

  // String to sign
  const credentialScope = `${dateStamp}/${requestOptions.region}/${requestOptions.service}/aws4_request`
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    hashedCanonicalRequest,
  ].join('\n')

  // Signing key
  const kDate = crypto.createHmac('sha256', 'AWS4' + secretAccessKey).update(dateStamp).digest()
  const kRegion = crypto.createHmac('sha256', kDate).update(requestOptions.region).digest()
  const kService = crypto.createHmac('sha256', kRegion).update(requestOptions.service).digest()
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest()

  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex')

  // Fill in the headers
  requestOptions.headers['X-Amz-Content-Sha256'] = payloadHash
  requestOptions.headers['X-Amz-Date'] = amzDate
  requestOptions.headers['Authorization'] =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`

  return requestOptions
}

const hexEncode = (c: string) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`

const escapeUri = (uri: string): string =>
  // AWS percent-encodes some extra non-standard characters in a URI
  encodeURIComponent(uri).replace(/[!'()*]/g, hexEncode)

export const buildQueryString = (query: QueryParameterBag): string => {
  const parts: string[] = []
  for (let key of Object.keys(query).sort()) {
    const value = query[key]
    key = escapeUri(key)
    if (Array.isArray(value)) {
      for (let i = 0, iLen = value.length; i < iLen; i++) {
        parts.push(`${key}=${escapeUri(value[i])}`)
      }
    } else {
      let qsEntry = key
      if (value || typeof value === 'string') {
        qsEntry += `=${escapeUri(value)}`
      }
      parts.push(qsEntry)
    }
  }

  return parts.join('&')
}

export const formatUrl = (
  request: Omit<IHttpRequest, 'headers' | 'method'>,
): string => {
  const { port, query } = request
  let { protocol, path, hostname } = request
  if (protocol && protocol.slice(-1) !== ':') {
    protocol += ':'
  }
  if (port) {
    hostname += `:${port}`
  }
  if (path && path.charAt(0) !== '/') {
    path = `/${path}`
  }
  let queryString = query ? buildQueryString(query) : ''
  if (queryString && queryString[0] !== '?') {
    queryString = `?${queryString}`
  }
  let auth = ''
  if (request.username != null || request.password != null) {
    const username = request.username ?? ''
    const password = request.password ?? ''
    auth = `${username}:${password}@`
  }
  let fragment = ''
  if (request.fragment) {
    fragment = `#${request.fragment}`
  }
  return `${protocol}//${auth}${hostname}${path}${queryString}${fragment}`
}

export const fromEnv = (filebaseToken: string): () => AwsCredentialIdentity => {
  return () => {
    const [accessKeyId, secretAccessKey] = atob(filebaseToken).split(':').map((s) => s.trim())
    if (!accessKeyId || !secretAccessKey) {
      throw new Error('Missing access key ID and secret access key')
    }
    return {
      accessKeyId,
      secretAccessKey,
    }
  }
}

export const createBucket = async (
  { bucketName, apiUrl, token }: RequiredArgs,
) => {
  let requestOptions: RequestOptions = {
    host: `${bucketName}.${apiUrl ?? FILEBASE_API_URL}`,
    region: 'us-east-1',
    method: 'PUT',
    service: 's3',
    headers: {
      'Content-Length': 0,
    },
    path: '/',
  }
  requestOptions = generateFilebaseRequestOptions(token, requestOptions)

  const res = await fetch(`https://${requestOptions.host}/`, requestOptions as unknown as RequestInit)
  if (res.ok) return
  // Throw instead of failing silently: a missing bucket otherwise only shows
  // up later as a confusing NoSuchBucket on upload.
  const body = await res.text()
  const code = body.match(/<Code>(.*?)<\/Code>/)?.[1]
  // S3 outside us-east-1 answers 409 for an existing own bucket.
  if (code === 'BucketAlreadyOwnedByYou') return
  const message = body.match(/<Message>(.*?)<\/Message>/)?.[1]
  throw new Error(`Failed to create bucket "${bucketName}": ${code ?? res.status} ${message ?? res.statusText}`)
}

const sign = (key: Uint8Array | string, msg: string): Uint8Array =>
  new Uint8Array(createHmac('sha256', key).update(msg).digest())

function getSignatureKey(secretKey: string, date: string, region: string, service: string): Uint8Array {
  const kDate = sign(`AWS4${secretKey}`, date)
  const kRegion = sign(kDate, region)
  const kService = sign(kRegion, service)
  return sign(kService, 'aws4_request')
}

export function presignRequest(
  request: IHttpRequest,
  {
    accessKeyId,
    secretAccessKey,
    region,
    expiresIn = 3600,
  }: {
    accessKeyId: string
    secretAccessKey: string
    region: string
    expiresIn?: number
  },
): IHttpRequest {
  const method = request.method.toUpperCase()
  const host = request.hostname
  const now = new Date()
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '')
  const dateStamp = amzDate.slice(0, 8)

  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`
  const credential = `${accessKeyId}/${credentialScope}`

  const signedHeaders = 'host'
  const query: Record<string, string> = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credential,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': signedHeaders,
  }

  const canonicalQuery = Object.entries(query)
    .sort()
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&')

  const canonicalRequest = [
    method,
    request.path,
    canonicalQuery,
    `host:${host}`,
    '',
    signedHeaders,
    'UNSIGNED-PAYLOAD',
  ].join('\n')

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n')

  const signingKey = getSignatureKey(secretAccessKey, dateStamp, region, 's3')
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex')

  return {
    ...request,
    query: {
      ...query,
      'X-Amz-Signature': signature,
    },
  }
}
