import { describe, it } from '@std/testing/bdd'
import { assertEquals, assertMatch, assertRejects, assertThrows } from '@std/assert'
import {
  createBucket,
  fromEnv,
  generateFilebaseRequestOptions,
  parseUrl,
  presignRequest,
  type RequestOptions,
} from './utils.ts'
import type { HttpRequest } from '@smithy/types'
import { assertObjectMatch } from '@std/assert/object-match'

describe('parseUrl', () => {
  describe('should return the correct parsed URL', () => {
    it('with protocol', () => {
      const url = 'https://example.com/path'
      const parsedUrl = parseUrl(url)
      assertEquals(parsedUrl.protocol, 'https:')
      assertEquals(parsedUrl.hostname, 'example.com')
    })
    it('with port', () => {
      const url = 'http://example.com:8080/path'
      const parsedUrl = parseUrl(url)
      assertEquals(parsedUrl.port, 8080)
    })
  })

  it('should throw error for invalid URL', () => {
    const url = 'not a valid url'
    assertThrows(() => {
      parseUrl(url)
    })
  })
})

describe('presignRequest', () => {
  it('should return a signed request', () => {
    const request: HttpRequest = {
      method: 'GET',
      hostname: 'example.com',
      path: '/path',
      query: {},
      headers: {},
      username: '',
      password: '',
      fragment: '',
      protocol: 'https:',
    }
    const signedRequest = presignRequest(request, {
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      region: 'us-east-1',
      expiresIn: 3600,
    })

    const now = new Date()
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '')
    const amzShortDate = amzDate.slice(0, 8)

    assertEquals(signedRequest.method, 'GET')
    assertEquals(signedRequest.hostname, 'example.com')
    assertEquals(signedRequest.path, '/path')
    assertObjectMatch(signedRequest.query!, {
      'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
      'X-Amz-Credential': `AKIAIOSFODNN7EXAMPLE/${amzShortDate}/us-east-1/s3/aws4_request`,
      'X-Amz-Date': amzDate,
      'X-Amz-Expires': '3600',
      'X-Amz-SignedHeaders': 'host',
    })
    assertEquals(signedRequest.headers, {})
  })
})

describe('generateFilebaseRequestOptions', () => {
  it('should throw if no token is provided', () => {
    assertThrows(() => generateFilebaseRequestOptions('lol', {} as RequestOptions))
  })
})

describe('fromEnv', () => {
  it('should throw if no token is provided', () => {
    assertThrows(() => fromEnv('lol')())
  })
})

describe('createBucket', () => {
  const token = btoa('key:secret')
  const stubFetch = (status: number, body = '') => {
    const calls: RequestInit[] = []
    const original = globalThis.fetch
    globalThis.fetch = ((_url: string, init: RequestInit) => {
      calls.push(init)
      return Promise.resolve(new Response(body, { status }))
    }) as typeof fetch
    return { calls, restore: () => (globalThis.fetch = original) }
  }

  it('should sign with a valid x-amz-date', async () => {
    const { calls, restore } = stubFetch(200)
    try {
      await createBucket({ bucketName: 'b', token })
      const date = (calls[0].headers as Record<string, string>)['X-Amz-Date']
      assertMatch(date, /^\d{8}T\d{6}Z$/)
    } finally {
      restore()
    }
  })

  it('should throw the S3 error when creation fails', async () => {
    const { restore } = stubFetch(
      409,
      '<Error><Code>BucketAlreadyExists</Code><Message>The requested bucket name is not available.</Message></Error>',
    )
    try {
      await assertRejects(() => createBucket({ bucketName: 'b', token }), Error, 'BucketAlreadyExists')
    } finally {
      restore()
    }
  })

  it('should accept a bucket the caller already owns', async () => {
    const { restore } = stubFetch(409, '<Error><Code>BucketAlreadyOwnedByYou</Code></Error>')
    try {
      await createBucket({ bucketName: 'b', token })
    } finally {
      restore()
    }
  })
})
