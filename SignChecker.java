// PoC for CVE-2022-21449
// Run with Java <= 17.0.2 / fixed in Java 17.0.3
// https://neilmadden.blog/2022/04/19/psychic-signatures-in-java

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.Exception;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class SignChecker
{
	private final String SignatureAlgorithm = "SHA256WithECDSAInP1363Format";
	private final int SignatureAlgorithmLength = (256 / 8) * 2;
	private KeyPair ecKeyPair;

	public static void main(String[] args)
	{
		if (2 > args.length)
		{
			showUsage();
			return;
		}

		String message = args[0];
		String providedSignature = args[1];

		try
		{
			System.out.format("Message: '%s'\r\n", message);

			SignChecker signChecker = new SignChecker();

			String signature = signChecker.sign(message);
			System.out.format("Own signature: '%s'\r\n", signature);
			boolean isCorrect = signChecker.verify(message, signature);
			System.out.format("Verifying own signature: %s\r\n", isCorrect ? "true" : "false");

			System.out.format("Provided signature '%s'\r\n", providedSignature);
			isCorrect = signChecker.verify(message, providedSignature);
			System.out.format("Verifying provided signature: %s\r\n", isCorrect ? "true" : "false");
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	}

	private static void showUsage()
	{
		System.out.println("Test tool to demonstrate the vulnerability of CVE-2022-21449.\r\nUsage:\r\n   java SignChecker [message] [signature]");
	}

	public SignChecker() throws NoSuchAlgorithmException, FileNotFoundException, IOException, Exception
	{
		loadKeyPair();
	}

	private void loadKeyPair() throws NoSuchAlgorithmException, FileNotFoundException, IOException, Exception
	{
		File currentDirectory = new File("").getAbsoluteFile();
		File privateKeyFile = new File(currentDirectory, "keyPairPrivate.txt");
		File publicKeyFile = new File(currentDirectory, "keyPairPublic.txt");
		KeyPairGenerator ecKeyGenerator = KeyPairGenerator.getInstance("EC");

		if (privateKeyFile.exists() && publicKeyFile.exists())
		{
			System.out.println("Using key files");
			try (FileInputStream privateKeyFileStream = new FileInputStream(privateKeyFile))
			{
				try (FileInputStream publicKeyFileStream = new FileInputStream(publicKeyFile))
				{
					long privateKeyFileLength = privateKeyFile.length();
					byte[] keyPairPrivateBytes = new byte[(int)privateKeyFileLength];
					int bytesRead = privateKeyFileStream.read(keyPairPrivateBytes);
					if (privateKeyFileLength != bytesRead)
					{
						String errorMessage = String.format("Could not read private key from file (privateKeyFileLength: %d / bytesRead: %d)", privateKeyFileLength, bytesRead);
						throw new Exception(errorMessage);
					}

					long publicKeyFileLength = publicKeyFile.length();
					byte[] keyPairPublicBytes = new byte[(int)publicKeyFileLength];
					bytesRead = publicKeyFileStream.read(keyPairPublicBytes);
					if (publicKeyFileLength != bytesRead)
					{
						String errorMessage = String.format("Could not read private key from file (publicKeyFileLength: %d / bytesRead: %d)", publicKeyFileLength, bytesRead);
						throw new Exception(errorMessage);
					}

					KeyFactory keyFactory = KeyFactory.getInstance("EC");
					PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(keyPairPublicBytes)));
					PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyPairPrivateBytes)));
					ecKeyPair = new KeyPair(publicKey, privateKey);

					return;
				}
			}
		}

		System.out.println("Generating key pair");
		ecKeyPair = ecKeyGenerator.generateKeyPair();

		try (FileOutputStream privateKeyFileStream = new FileOutputStream(privateKeyFile))
		{
			try (FileOutputStream publicKeyFileStream = new FileOutputStream(publicKeyFile))
			{
				privateKeyFileStream.write(Base64.getEncoder().encode(ecKeyPair.getPrivate().getEncoded()));
				publicKeyFileStream.write(Base64.getEncoder().encode(ecKeyPair.getPublic().getEncoded()));
			}
		}
	}

	public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, Exception
	{
		Signature ecSignature = Signature.getInstance(SignatureAlgorithm);
		ecSignature.initSign(ecKeyPair.getPrivate());

		ecSignature.update(message.getBytes());
		final int SignatureBufferLength = 128;
		byte[] signatureBuffer = new byte[SignatureBufferLength];
		int bytesWritten = ecSignature.sign(signatureBuffer, 0, SignatureBufferLength);
		signatureBuffer = Arrays.copyOf(signatureBuffer, bytesWritten);

		return Base64.getEncoder().encodeToString(signatureBuffer);
	}

	public boolean verify(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		Signature ecSignature = Signature.getInstance(SignatureAlgorithm);
		ecSignature.initVerify(ecKeyPair.getPublic());

		byte[] messageBytes = message.getBytes();
		ecSignature.update(messageBytes);

		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		return ecSignature.verify(signatureBytes);
	}
}
