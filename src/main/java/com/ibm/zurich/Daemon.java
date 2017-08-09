package com.ibm.zurich;

import java.math.BigInteger;
import java.util.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.ibm.zurich.Authenticator;
import com.ibm.zurich.Authenticator.EcDaaSignature;
import com.ibm.zurich.Verifier;
import com.ibm.zurich.Issuer.IssuerPublicKey;
import com.ibm.zurich.Issuer.IssuerSecretKey;
import com.ibm.zurich.Issuer.JoinMessage1;
import com.ibm.zurich.Issuer.JoinMessage2;
import com.ibm.zurich.crypto.BNCurve;
import com.ibm.zurich.crypto.BNCurve.BNCurveInstantiation;

/**
 * Class to run as a daemon,
 * producing or verifying signatures on-demand
 * via a named pipe.
 * @author zanebeckwith
 */
public class Daemon {
        private BNCurve curve;

        private IssuerPublicKey ipk;

        private Authenticator auth;

        private Verifier ver;

        private RandomAccessFile pipe;

        private Path tmp_fifoPath = Paths.get("/tmp/xaptum_ecdaa_daemon_pipe");

        private String tmp_ipk_string = "{\"EcDaaTrustAnchor\":{\"X\":\"BLbzZnMBEYztz-9mUZVx0D0x5gZUGw_RvvQhuF5LUimp7p8ilTcZaJz-h1qaOauKkKmjS5mHQMHmi94YPjCQgYeq9az574oUYBMsohSnh9PujGDNS3hTBXX4nFUIZuxUm9u9sH2dIKzNqmPtCPJFMErOFJMtd7KuprFKeN2PPKL9\",\"Y\":\"BNb73A7VTTGGaSqejxaCz4PW7bsdf2cHoyEYrlvtwqD5WXs2niH1BKQay_vAGuQyQP6uUqMDU0VR07_91ZdTssf23TK4IlmX3CHiUZOdYV11hhi6TODXk6uA2jNd1bg004QPkxS4gpb6R_fcj39cF18rLUu4cr5lDNk7xjbXhC_e\",\"c\":\"i3pfhffzh-xI_hdTi2JSLoqx9BuNekce8rRbFp3DO44=\",\"sx\":\"VlsjhXAxgjTuWepVwO7ll48DndHpLBOXAkZ2n_eKVIY=\",\"sy\":\"qIS5ovAHbgauhduFKUOTj68ghvcFWLgtI7FV7suB32o=\"}}";


        private String tmp_auth_string = "13Loevj0A00YjvUeDk-24oww-6BHUATG1l7oGm-fFWM=";


        private String tmp_join_msg2_string = "{\"JoinMessage2\":{\"a\":\"BJ1T5TT9cylAbtvwruUg_5lxjp4rF3vfuKypNTFF4cWmYuYcDCgRWsWHO5G92j31i8DNHt9aER-QsJrgV4MN3hc=\",\"b\":\"BAPvoljKrBwJ96G9N4IZuwudpEtBcKVjZSjtoaVOd3Fj0GLRZq4nTOu5nsht4OY5rzcyg1Z1s08O9bQwFBMUC6Y=\",\"c\":\"BMGXLI1okegGFo3SlYeHHTtZ8eidEZKJBPjRFXhBz3zktDkC21YrmPZ-0BZesVPcqRfK3VoGe1va-n_Kx-p6x38=\",\"d\":\"BF37KgB0wFTKiQ8yHVTp2jOKdPJLfUks7EXQLD_Q94vHPntSa9WKcNYJimTafXy6XeM-pNyZXRiiMsTMqFELmBQ=\",\"c2\":\"BMup5c7H8PVplk7XCNdQHDna25mv6vD-TOGEIfUJALA=\",\"s2\":\"TY27MuCy5ZY-8RjKKdrdy5ql8UasYUl4xTFeglK67Y8=\"}}";

        private String tmp_curve_type_string = "TPM_ECC_BN_P256";

        private byte[] tmp_krd;

        private String tmp_rl_list_string = "{\"RogueList\":[]}";

        public Daemon(String configFilename) throws NoSuchAlgorithmException, IOException, InterruptedException {
                // TODO Figure out what to do with config file

                SetupCurve();

                CreateAuthenticator();

                CreateVerifier();

                OpenNamedPipe();
        }

        public void Run() {
                System.out.println("Starting daemon");

                try {
                        while (true) {
                                String in_message = this.pipe.readLine();
                                System.out.println("Got message: " + in_message);
                        }
                } catch (IOException e) {
                        System.out.println("ERROR, exception thrown:");
			e.printStackTrace();
                }
                // String message = "This is a message";

                // try {
                //         byte[] signature = Sign(message);

                //         if (!Verify(message, signature)) {
                //                 System.out.println("ERROR verifying signature");
                //         } else {
                //                 System.out.println("Verified signature");
                //         }
		// } catch (NoSuchAlgorithmException e) {
                //         System.out.println("ERROR, exception thrown:");
		// 	e.printStackTrace();
		// }
        }

        private void SetupCurve() {
                BNCurveInstantiation instantiation = BNCurveInstantiation.valueOf(tmp_curve_type_string);
                this.curve = new BNCurve(instantiation);
        }

        private void CreateAuthenticator() throws NoSuchAlgorithmException, RuntimeException {
                this.ipk = new IssuerPublicKey(this.curve, this.tmp_ipk_string);
                
		Base64.Decoder decoder = Base64.getUrlDecoder();
                BigInteger authsk = this.curve.bigIntegerFromB(decoder.decode(this.tmp_auth_string));

                JoinMessage2 msg2 = new JoinMessage2(this.curve, this.tmp_join_msg2_string);
                
		SecureRandom random = new SecureRandom();

                this.auth = new Authenticator(this.curve, ipk, authsk);
                auth.EcDaaJoin1(curve.getRandomModOrder(random));
                if(!auth.EcDaaJoin2(msg2)) {
                        throw new RuntimeException("ERROR creating Authenticator");
                }
        }

        private void CreateVerifier() {
                this.ver = new Verifier(curve);
        }

        private void OpenNamedPipe() throws IOException, InterruptedException {
                Files.deleteIfExists(this.tmp_fifoPath);

                Process process = null;
                String[] command_make = new String[] {"mkfifo", this.tmp_fifoPath.toString()};
                process = new ProcessBuilder(command_make).inheritIO().start();
                process.waitFor();

                this.pipe = new RandomAccessFile(this.tmp_fifoPath.toString(), "r");
        }

        private byte[] Sign(String message) throws NoSuchAlgorithmException {
                EcDaaSignature sig = this.auth.EcDaaSign(message);

                // TODO: Get away from using the KRD crap
                this.tmp_krd = sig.krd;

                return sig.encode(curve);
        }

        private boolean Verify(String message, byte[] signature) throws NoSuchAlgorithmException {
                EcDaaSignature sig = new EcDaaSignature(signature, this.tmp_krd, this.curve);
                return this.ver.verify(sig,
                                       message,
                                       this.ipk,
                                       Verifier.revocationListFromJson(
						this.tmp_rl_list_string, this.curve));
        }
}
