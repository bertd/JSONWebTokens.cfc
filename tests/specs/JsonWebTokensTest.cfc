component
	extends = "TestCase"
	output = false
	hint = "I test the JSON Web Tokens component."
	{

	public void function test_that_the_client_works() {

		var jwtClient = new lib.JsonWebTokens().createClient( "HS256", "secret" );

		// NOTE: Values pulled from http://jwt.io/
		var payload = {
			"sub": "1234567890",
			"name": "John Doe",
			"admin": true
		};

		// NOTE: Because we the order of the serialized keys affects the token, it's hard 
		// to consistently test the encoded value. But, we can test the full life-cycle 
		// and ensure that the decoded value matches the original input.
		var token = jwtClient.encode( payload );
		var newPayload = jwtClient.decode( token );

		assert( payload.sub == newPayload.sub );
		assert( payload.name == newPayload.name );
		assert( payload.admin == newPayload.admin );

	}


	public void function test_that_hmac_decoding_works() {

		var jwt = new lib.JsonWebTokens();

		// NOTE: Values pulled from http://jwt.io/
		var payload = jwt.decode( 
			"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoxMjM0NTY3ODkwfQ.5lwOHou_CUazP24HNO4Zc0MQVMay5e48eCIsiJYZAs0", 
			"HS256",
			"secret"
		);

		assert( payload.sub == "1234567890" );
		assert( payload.name == "John Doe" );
		assert( payload.admin == true );

	}


	public void function test_that_rsa_decoding_works() {

		var jwt = new lib.JsonWebTokens();

		// NOTE: Values pulled from http://jwt.io/
		var payload = jwt.decode( 
			"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.RmVuOo-h-m2xCHTa2Cj6lz3rc6INhJS4cnq5DAiGTZekfoiiSnoEaehzvYiiEFjr6coNx4YKzV6CkcFrnbgC1AuZGbEAsg6TgQqljRke_6rKWKyp46kE1zc8z0SLdGHu9ELZu_MKRH6QwlLPuoCWcPrKnN65bQIyJ89qCnUfVDaRldKKKv_Vf77_pXtxgqAL0bhZmPG8gfApi5ziZ4uK_PMZVScbPLKpfSuuQvReMWWPIyg-u79_n0HdLY5Bw1m3AflCOzP9Nb-yNdVU6BlHOV1ZJ_YKjnA9zT_mgkgorQmwdy36JUYkyUuL5_sfZu627MDslc6Bg96pFcmqJ-QN9w",
			"RS256",
			getPublicKey(),
			getPrivateKey()
		);

		assert( payload.sub == "1234567890" );
		assert( payload.name == "John Doe" );
		assert( payload.admin == true );

	}


	public void function test_that_hmac_encoding_lifecycle_works() {

		var jwt = new lib.JsonWebTokens();

		var payload = {
			"sub": "1234567890",
			"name": "John Doe",
			"admin": true
		};

		// NOTE: Because we the order of the serialized keys affects the token, it's hard 
		// to consistently test the encoded value. But, we can test the full life-cycle 
		// and ensure that the decoded value matches the original input.
		var token = jwt.encode( payload, "HS256", "secret" );
		var newPayload = jwt.decode( token, "HS256", "secret" );

		assert( payload.sub == newPayload.sub );
		assert( payload.name == newPayload.name );
		assert( payload.admin == newPayload.admin );

	}


	public void function test_that_rsa_encoding_lifecycle_works() {

		var jwt = new lib.JsonWebTokens();

		var payload = {
			"sub": "1234567890",
			"name": "John Doe",
			"admin": true
		};

		// NOTE: Because we the order of the serialized keys affects the token, it's hard 
		// to consistently test the encoded value. But, we can test the full life-cycle 
		// and ensure that the decoded value matches the original input.
		var token = jwt.encode( payload, "RS256", getPublicKey(), getPrivateKey() );
		var newPayload = jwt.decode( token, "RS256", getPublicKey(), getPrivateKey() );

		assert( payload.sub == newPayload.sub );
		assert( payload.name == newPayload.name );
		assert( payload.admin == newPayload.admin );

	}


	public void function test_complex_data_with_hmac_encoding_lifecycle() {

		var algorithms = [ "HS256", "HS384", "HS512" ];

		// Try it for each supported algorithm.
		for ( algorithm in algorithms ) {

			var jwtClient = new lib.JsonWebTokens().createClient( algorithm, "secret" );

			var payload = {
				"id": 4,
				"name": "Kim Smith",
				"likes": [ "Movies", "Walks", "Food" ],
				"strengths": {
					"kindness": 7,
					"quirkiness": 9,
					"fun": 10
				}
			};

			// NOTE: Because we the order of the serialized keys affects the token, it's hard 
			// to consistently test the encoded value. But, we can test the full life-cycle 
			// and ensure that the decoded value matches the original input.
			var token = jwtClient.encode( payload );
			var newPayload = jwtClient.decode( token );

			assert( payload.id == newPayload.id );
			assert( payload.name == newPayload.name );
			assert( payload.likes[ 1 ] == "Movies" );
			assert( payload.likes[ 2 ] == "Walks" );
			assert( payload.likes[ 3 ] == "Food" );
			assert( payload.strengths.kindness == newPayload.strengths.kindness );
			assert( payload.strengths.quirkiness == newPayload.strengths.quirkiness );
			assert( payload.strengths.fun == newPayload.strengths.fun );
			
		}

	}


	public void function test_complex_data_with_rsa_encoding_lifecycle() {

		var algorithms = [ "RS256", "RS384", "RS512" ];

		// Try it for each supported algorithm.
		for ( algorithm in algorithms ) {

			var jwtClient = new lib.JsonWebTokens().createClient( algorithm, getPublicKey(), getPrivateKey() );

			var payload = {
				"id": 4,
				"name": "Kim Smith",
				"likes": [ "Movies", "Walks", "Food" ],
				"strengths": {
					"kindness": 7,
					"quirkiness": 9,
					"fun": 10
				}
			};

			// NOTE: Because we the order of the serialized keys affects the token, it's hard 
			// to consistently test the encoded value. But, we can test the full life-cycle 
			// and ensure that the decoded value matches the original input.
			var token = jwtClient.encode( payload );
			var newPayload = jwtClient.decode( token );

			assert( payload.id == newPayload.id );
			assert( payload.name == newPayload.name );
			assert( payload.likes[ 1 ] == "Movies" );
			assert( payload.likes[ 2 ] == "Walks" );
			assert( payload.likes[ 3 ] == "Food" );
			assert( payload.strengths.kindness == newPayload.strengths.kindness );
			assert( payload.strengths.quirkiness == newPayload.strengths.quirkiness );
			assert( payload.strengths.fun == newPayload.strengths.fun );
			
		}

	}


	public void function test_complex_data_with_hmac_decoding() {

		var jwtClient = new lib.JsonWebTokens().createClient( "HS256", "secret" );

		// NOTE: Because we the order of the serialized keys affects the token, it's hard 
		// to consistently test the encoded value. But, we can test that the decoded value
		// matches a known encoded token.
		// --
		// Signature validated on http://jwt.io/
		var newPayload = jwtClient.decode( "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NCwibmFtZSI6IktpbSBTbWl0aCIsImxpa2VzIjpbIk1vdmllcyIsIldhbGtzIiwiRm9vZCJdLCJzdHJlbmd0aHMiOnsia2luZG5lc3MiOjcsInF1aXJraW5lc3MiOjksImZ1biI6MTB9fQ.QKkMlaC0mSCryIwcmI7sIJ_WfY6n0a8DmkjJYajk100" );

		var expectedPayload = {
			"id": 4,
			"name": "Kim Smith",
			"likes": [ "Movies", "Walks", "Food" ],
			"strengths": {
				"kindness": 7,
				"quirkiness": 9,
				"fun": 10
			}
		};

		assert( expectedPayload.id == newPayload.id );
		assert( expectedPayload.name == newPayload.name );
		assert( expectedPayload.likes[ 1 ] == "Movies" );
		assert( expectedPayload.likes[ 2 ] == "Walks" );
		assert( expectedPayload.likes[ 3 ] == "Food" );
		assert( expectedPayload.strengths.kindness == newPayload.strengths.kindness );
		assert( expectedPayload.strengths.quirkiness == newPayload.strengths.quirkiness );
		assert( expectedPayload.strengths.fun == newPayload.strengths.fun );

	}


	public void function test_complex_data_with_rsa_decoding() {

		var jwtClient = new lib.JsonWebTokens().createClient( "RS256", getPublicKey(), getPrivateKey() );

		// NOTE: Because we the order of the serialized keys affects the token, it's hard 
		// to consistently test the encoded value. But, we can test that the decoded value
		// matches a known encoded token.
		// --
		// Signature validated on http://jwt.io/
		var newPayload = jwtClient.decode( "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NCwibmFtZSI6IktpbSBTbWl0aCIsImxpa2VzIjpbIk1vdmllcyIsIldhbGtzIiwiRm9vZCJdLCJzdHJlbmd0aHMiOnsia2luZG5lc3MiOjcsInF1aXJraW5lc3MiOjksImZ1biI6MTB9fQ.hAfSM1DdfBIRhxydByGO-P6poyN6odQ8fg1STh25zPx-6QwydlQp9nbLLm294BB3c3uLewJrBpXCRuRSHTtzza4WP3wON2V4SUT3J6P1tvOR7AOk-bAhkmcEQUYnXmQIvzgrcGUdkE-QJX2qXN7_QrlYL2tcWRUWhZe_P13cX3WJIOQWlZGjfT8_Icrj70qmATlCCPFBQ_3RcnDGrna2EHoFiq_6SKnbYAQbhb2yv2VClteD1WznrK-iTgO8k-4OfE2oPrP4JhGoqUIjy7SYzYnaVg8uJCN8i8oQ72BfdR6bwvqE6O96g90P2jBbLPKgtCfFzGsdlZIKCTgT8dVvWg" );

		var expectedPayload = {
			"id": 4,
			"name": "Kim Smith",
			"likes": [ "Movies", "Walks", "Food" ],
			"strengths": {
				"kindness": 7,
				"quirkiness": 9,
				"fun": 10
			}
		};

		assert( expectedPayload.id == newPayload.id );
		assert( expectedPayload.name == newPayload.name );
		assert( expectedPayload.likes[ 1 ] == "Movies" );
		assert( expectedPayload.likes[ 2 ] == "Walks" );
		assert( expectedPayload.likes[ 3 ] == "Food" );
		assert( expectedPayload.strengths.kindness == newPayload.strengths.kindness );
		assert( expectedPayload.strengths.quirkiness == newPayload.strengths.quirkiness );
		assert( expectedPayload.strengths.fun == newPayload.strengths.fun );

	}


	public void function test_that_hmac_algorithms_result_in_different_tokens() {

		var jwt = new lib.JsonWebTokens();

		var payload = {
			"id": 4,
			"name": "Kim Smith"
		};

		var token256 = jwt.encode( payload, "HS256", "secret" );
		var token384 = jwt.encode( payload, "HS384", "secret" );
		var token512 = jwt.encode( payload, "HS512", "secret" );

		assert( token256 != token384 );
		assert( token256 != token512 );
		assert( token384 != token512 );

	}


	public void function test_that_rsa_algorithms_result_in_different_tokens() {

		var jwt = new lib.JsonWebTokens();

		var payload = {
			"id": 4,
			"name": "Kim Smith"
		};

		var token256 = jwt.encode( payload, "RS256", getPublicKey(), getPrivateKey() );
		var token384 = jwt.encode( payload, "RS384", getPublicKey(), getPrivateKey() );
		var token512 = jwt.encode( payload, "RS512", getPublicKey(), getPrivateKey() );

		assert( token256 != token384 );
		assert( token256 != token512 );
		assert( token384 != token512 );

	}


	// ---
	// PRIVATE METHODS.
	// ---


	// I get the private RSA key in PEM format.
	private string function getPrivateKey() {

		var lines = [
			"-----BEGIN PRIVATE KEY-----",
			"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRv/mlsrxWufLJ",
			"doRRhBU/YQjfFkOzsPYpZKgdlyTCGe5SyQXUo+MwuzYWjlyUg4GrkeJiCLJjqTQb",
			"FxpPq/c/51TdGjb6JvDHNfX+ExqKvt1+BwiTYWFnv1F3r08UDpZhkTfhY3ZkyAMJ",
			"0EbSvWFA8KamC3q0KfocFhReRSKFRQBG9KJo8+1nSjT9nNG4rq0L/ZY1fXbEOPeY",
			"sAJhAuo4hQrBbYn0783c2x5nnV1B5eNnUBBPf82a9fhzU98U/oY2iJ2/UIutouZk",
			"iK7D4pIjwjyYYspAHrRW5J0PT25ZeaCqZxK41+WdhZ9l+9bd2pZcKyV3noVOSy8f",
			"Po9d/kBZAgMBAAECggEAUBAvgwhOy+v+uNf8egEo+yBW+pDNFvIdhH9fjKv84/px",
			"9je1eg10000iwElnHWl1PcBZ4YHgVhpoQU74RCEoJ8RtqFgxVBs5HVGDrJAuOXfR",
			"pCGbLGanf6qPtle8n7NRw7xi0C3fK2kNf9l4r0iKrvctJYSMOeksBzyGWdWZ77RN",
			"XU0g76qa2eyzjcYeVAJWYfpQToJ/mmjd1Wi+/QKEjdbEzojBBTOyiDfgzkOSX5pA",
			"v96Dg0Ow111te2Q/OEzZESziywUy9XBDuFbmWMnYt/OTJ+GCFcE4lW5QtMl3oPUI",
			"p1osYy9EdsUDw3Dmz62Z3Dn3glhKjrrNptIclCzn4QKBgQD9sejHk/CDShRHmTIp",
			"p5jZ1i/liQ8AFZQSazkFw/AOqbyt3x70brv+be37WVo0seUU1iV/a2x/uRoBdASl",
			"lFmNq1vVExE2yb4ex0asRNtDAvRVp0aiPLQlhZ1NG+GdRce9tXbZdk0BxBJaacOi",
			"IS4Z6LRbyOQFYl0yixyQLCyv4wKBgQDTp9mwIUcX32e6hvKYvFhw18/1hArEptyl",
			"AtOItkYCRwhbMUCW2uMXb81coK2+WQXMFt0VqXdi5BZeY0CLKOwug771dJPW82pg",
			"NZYu3yOer1+tMJdtxad8AHIQ9oSH3Mu9f5fZqmUnFTLQUbk00Bz03A045X/+/Xnv",
			"dpS9jeeLkwKBgQCOBhhMCn0d8s3Rm2jiuumuIeNke8tC/9GKUi51FNECVHHFYOCC",
			"dK+X61DMYqRGVcTqWkxZvfjas/RkFeA4FgngbqsVaPw9EMn3jxX4gP/CzxecD+5S",
			"CuvLCbcbIN24XwVIJhun+Dt6HpsrtIQJ8stNQ+IcdCV7AissjYZrC9/kgwKBgQCA",
			"QJWIRKHvtVAFlwApzPdKaXt6KijcQMAyvSOxE8IYXzKRD6czwi8ZZIXsOvENBqSc",
			"pr4RAj91jQCA8WOK76EuDmcIFTwAZD9xTQdUH6JV5a70Ix2fRsXWPe7gmIB2UzSh",
			"/07kdnwU0qOX1+2CMxlYxn68m1SUDsR0dkZrFjHYQQKBgCegmRpxpW0/vb3ApvXX",
			"ynCNhnWbtBHnlaDkHT3kO4W4t7JVAvsRGxDYTTTus8rdTh7IkdnXJFfSowdtCEB/",
			"XcIfqIh/5BmDYYPuFC6DPKsKWQdeT1UMobgDoC3gdWljoNRPaSs/akPa9wwGb1bU",
			"CM6RyC2uULvKVimFJYy92Q6H",
			"-----END PRIVATE KEY-----"
		];

		return( arrayToList( lines, chr( 10 ) ) );

	}


	// I get the public RSA key in PEM format.
	private string function getPublicKey() {

		var lines = [
			"-----BEGIN PUBLIC KEY-----",
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0b/5pbK8VrnyyXaEUYQV",
			"P2EI3xZDs7D2KWSoHZckwhnuUskF1KPjMLs2Fo5clIOBq5HiYgiyY6k0GxcaT6v3",
			"P+dU3Ro2+ibwxzX1/hMair7dfgcIk2FhZ79Rd69PFA6WYZE34WN2ZMgDCdBG0r1h",
			"QPCmpgt6tCn6HBYUXkUihUUARvSiaPPtZ0o0/ZzRuK6tC/2WNX12xDj3mLACYQLq",
			"OIUKwW2J9O/N3NseZ51dQeXjZ1AQT3/NmvX4c1PfFP6GNoidv1CLraLmZIiuw+KS",
			"I8I8mGLKQB60VuSdD09uWXmgqmcSuNflnYWfZfvW3dqWXCsld56FTksvHz6PXf5A",
			"WQIDAQAB",
			"-----END PUBLIC KEY-----"

		];

		return( arrayToList( lines, chr( 10 ) ) );

	}

}
