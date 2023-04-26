require('should');
const digestAuthHeader = require('../');

describe('index.test.js', function () {
  it('should create auth header', function () {
    var auth = 'Digest realm="test", nonce="AwrIOLT1BAA=c02c74925294185a304a50a27e25214fe4caafec", algorithm=MD5, domain="/auth-digest/", qop="auth"';
    var header = digestAuthHeader('GET', '/', auth, 'user1:pass1');
    header.should.include('Digest username="user1", realm="test", nonce="AwrIOLT1BAA=c02c74925294185a304a50a27e25214fe4caafec", uri="/", response="');
    header.should.include(', qop=auth, ');

    var serverAuth2 = 'Digest realm="me@kennethreitz.com", nonce="9fa37e281ff24157ce2ffece0778d04b", opaque="c6fb900fddb8797febbf3e3368999e70", qop=auth';
    header = digestAuthHeader('get', '/', serverAuth2, 'user2:pass2');
    header.should.include('opaque="c6fb900fddb8797febbf3e3368999e70"');
    header.should.include('Digest username="user2", realm="me@kennethreitz.com", nonce="9fa37e281ff24157ce2ffece0778d04b", uri="/", response="');
  });

  it('should support ream contains space', function () {
    var auth = 'Digest realm="phoenix app security", qop="auth", nonce="MTM5NjIzNTU4MjY4OToyMjFjY2U4MDA0YTJjZjExNzQ3ODIzYWY1NTY4YjczMQ=="';
    var header = digestAuthHeader('GET', '/', auth, 'user1:pass1');
    header.should.include('Digest username="user1", realm="phoenix app security", nonce="MTM5NjIzNTU4MjY4OToyMjFjY2U4MDA0YTJjZjExNzQ3ODIzYWY1NTY4YjczMQ==", uri="/", response="');
    header.should.include(', qop=auth, ');
  });

  it('should work for no qop', function () {
    var auth = 'Digest realm="test", nonce="AwrIOLT1BAA=c02c74925294185a304a50a27e25214fe4caafec", algorithm=MD5, domain="/auth-digest/"';
    var header = digestAuthHeader('GET', '/', auth, 'user1:pass1');
    header.should.equal('Digest username=\"user1\", realm=\"test\", nonce=\"AwrIOLT1BAA=c02c74925294185a304a50a27e25214fe4caafec\", uri=\"/\", response=\"5152194a5873b5136b8a320643424fdc\"');
  });

  it('should emtpy string when realm not exists', function () {
    var auth = 'Digest realm="", qop="auth", nonce="MTM5NjIzNTU4MjY4OToyMjFjY2U4MDA0YTJjZjExNzQ3ODIzYWY1NTY4YjczMQ=="';
    var header = digestAuthHeader('GET', '/', auth, 'user1:pass1');
    header.should.equal('');

    var auth = 'Digest qop="auth", nonce="MTM5NjIzNTU4MjY4OToyMjFjY2U4MDA0YTJjZjExNzQ3ODIzYWY1NTY4YjczMQ=="';
    var header = digestAuthHeader('GET', '/', auth, 'user1:pass1');
    header.should.equal('');
  });

  it('should emtpy string when nonce not exists', function () {
    var auth = 'Digest realm="test", qop="auth", nonce="" dd';
    var header = digestAuthHeader('GET', '/', auth, 'user1:pass1');
    header.should.equal('');

    var auth = 'Digest realm="test", qop="auth"';
    var header = digestAuthHeader('GET', '/', auth, 'user1:pass1');
    header.should.equal('');
  });
});
