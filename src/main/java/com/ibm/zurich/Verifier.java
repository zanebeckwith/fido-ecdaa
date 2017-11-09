/**
Copyright 2016 IBM Corp.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
**/
package com.ibm.zurich;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.StringJoiner;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.ibm.zurich.Authenticator.EcDaaSignature;
import com.ibm.zurich.Issuer.IssuerPublicKey;
import com.ibm.zurich.crypto.BNCurve;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.File;
import java.io.FileOutputStream;

/**
 * Class containing the Verifier ECDAA functions
 * @author manudrijvers 
 *
 */

public class Verifier {
	private BNCurve curve;
	public static String JSON_REVOCATION_LIST = "RogueList";
	public static String JSON_REVOCATION_LIST_ENTRY = "RogueListEntry";
	
	public Verifier(BNCurve curve) {
		this.curve = curve;
	}
	
	/**
	 * Verifies an ECDAA signature
	 * @param signature an ECDAA signature
	 * @param appId The AppID (i.e. https-URL of TrustFacets object)
	 * @param pk the Issuer public key
	 * @param revocationList the list of revoked private keys
	 * @return true iff the signature is valid
	 * @throws NoSuchAlgorithmException
	 */
	public boolean verify(EcDaaSignature signature, String appId, IssuerPublicKey pk, Set<BigInteger> revocationList) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		boolean success = true;
		
		// Check that a, b, c, d are in G1
		success &= this.curve.isInG1(signature.r);
                if (!success) System.out.println("r");
		success &= this.curve.isInG1(signature.s);
                if (!success) System.out.println("s");
		success &= this.curve.isInG1(signature.t);
                if (!success) System.out.println("t");
		success &= this.curve.isInG1(signature.w);
                if (!success) System.out.println("2");

		// Check that this is not the trivial credential (1, 1, 1, 1)
		success &= !this.curve.isIdentityG1(signature.r);
BigInteger my_c = this.curve.hashModOrder(this.curve.point1ToBytes(
						signature.s.multiplyPoint(signature.s2).subtractPoint(signature.w.multiplyPoint(signature.c2))),
				this.curve.point1ToBytes(signature.s),
				this.curve.point1ToBytes(signature.w),
				appId.getBytes());
if (my_c.compareTo(curve.getOrder()) == 1) System.out.println("greater");
if (my_c.signum() < 0) System.out.println("neg");
System.out.println(curve.bigIntegerToB(signature.c2));
System.out.println(curve.bigIntegerToB(my_c));

FileOutputStream fos3 = new FileOutputStream(new File("other_hash.bin"));
fos3.write(curve.bigIntegerToB(signature.c2));
fos3.flush();
fos3.close();
FileOutputStream fos2 = new FileOutputStream(new File("hash_output.bin"));
fos2.write(curve.bigIntegerToB(my_c));
fos2.flush();
fos2.close();
// FileOutputStream fos = new FileOutputStream(new File("hash_input.bin"));
// fos.write(this.curve.point1ToBytes(signature.s.multiplyPoint(signature.s2).subtractPoint(signature.w.multiplyPoint(signature.c2))));
// fos.write(this.curve.point1ToBytes(signature.s));
// fos.write(this.curve.point1ToBytes(signature.w));
// fos.write(appId.getBytes());
// fos.flush();
// fos.close();
		
		// Verify that c2, s2 proves SPK{(sk): w = s^sk}(krd, appId)
		success &= signature.c2.equals(my_c);
				// this.curve.hash(signature.krd)));
                if (!success) System.out.println("schnorr");
		
		// Verify credential
		success &= this.curve.pair(signature.r, pk.Y).equals(this.curve.pair(signature.s, this.curve.getG2()));
                if (!success) System.out.println("cred1");
		success &= this.curve.pair(signature.t, this.curve.getG2()).equals(
				this.curve.pair(signature.r.clone().addPoint(signature.w), pk.X));
                if (!success) System.out.println("cred2");

		// Perform revocation check
		if(revocationList != null) {
			for(BigInteger sk : revocationList) {
				success &= !signature.s.clone().multiplyPoint(sk).equals(signature.w);
			}
		}
                if (!success) System.out.println("rev");
		
		return success;
	}
	
	/**
	 * Turns a revocation list as a set of big integers into a JSON object
	 * @param revocationList The revocation list as a Set<BigInteger>
	 * @param curve The curve used
	 * @return The revocation list as a JSON object
	 */
	public static String revocationListToJson(Set<BigInteger> revocationList, BNCurve curve) {
		StringBuilder sb = new StringBuilder();
		Base64.Encoder encoder = Base64.getUrlEncoder();
		
		sb.append("{\"" + JSON_REVOCATION_LIST + "\":[");
		
		StringJoiner sj = new StringJoiner(",");
		for(BigInteger revoked : revocationList) {
			sj.add("{\"" + JSON_REVOCATION_LIST_ENTRY + "\":\"" + encoder.encodeToString(curve.bigIntegerToB(revoked)) + "\"}");
		}
		sb.append(sj.toString());
		sb.append("]}");
		
		return sb.toString();
	}
	
	/**
	 * Turns a revocation list as JSON object into a set of big integers
	 * @param json the revocation list as a JSON object
	 * @param curve the curve used
	 * @return the revocation list as a Set<BigInteger>
	 */
	public static Set<BigInteger> revocationListFromJson(String json, BNCurve curve) {
		Base64.Decoder decoder = Base64.getUrlDecoder();

		JsonArray object = new JsonParser().parse(json).getAsJsonObject().getAsJsonArray(JSON_REVOCATION_LIST);
		Set<BigInteger> rl = new HashSet<BigInteger>(object.size());
		for(JsonElement element : object) {
			rl.add(curve.bigIntegerFromB(decoder.decode(element.getAsJsonObject().get(JSON_REVOCATION_LIST_ENTRY).getAsString())));
		}
		return rl;
	}
}
