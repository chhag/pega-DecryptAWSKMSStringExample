import com.pega.pegarules.exec.internal.crypto.dataencryption.AWSKMSCredential;
import com.pega.pegarules.exec.internal.crypto.dataencryption.AWSKMSKeyMetadata;
import com.pega.pegarules.exec.internal.crypto.dataencryption.DataKey;
import com.pega.pegarules.exec.internal.crypto.dataencryption.InternalCryptography;
import com.pega.pegarules.exec.internal.crypto.dataencryption.KMSKeyMetadata;
import com.pega.pegarules.exec.internal.crypto.dataencryption.KeyDataBytes;
import com.pega.pegarules.exec.internal.crypto.dataencryption.KeyManagementService;
import com.pega.pegarules.exec.internal.crypto.dataencryption.KeyManagementServiceFactory;
import com.pega.pegarules.exec.internal.crypto.dataencryption.keys.cache.EncryptedDataKey;
import com.pega.pegarules.priv.util.Base64;
import com.pega.pegarules.pub.PRRuntimeException;
import com.pega.pegarules.pub.util.StringUtils;
import com.pega.platform.securitycore.encryption.KMSConstants.KMSType;
import java.nio.ByteBuffer;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import com.googlecode.concurrentlinkedhashmap.ConcurrentLinkedHashMap;
import com.googlecode.concurrentlinkedhashmap.ConcurrentLinkedHashMap.Builder;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import com.pega.pegarules.pub.context.ThreadContainer;


/**
 * <p>
 * Decrypts a proprietary Pega Platform encrypted string using an AWS CDK key stored in Pega using AWS KMS
 * 
 * <p>
 */
public class DecryptAWSStringExample {

    public static void main(final String[] args) {
		try {

			String s = "\t{pa}AAAAAf3GZ72UU6m4T1gsVHakJQE=";

			System.out.println("Encrypted:"+s);
			System.out.println("Decrypted:"+ decrypt(s));
		} catch(Exception e) {
			throw new PRRuntimeException("An error occurred during decryption ", e);
		}
    }
    
	private static String decrypt(String cipherText) {
		SimpleEntry<String, Boolean> keyStoreInfo = isValidKeyStore(cipherText);
		if (!(Boolean)keyStoreInfo.getValue()) {
			throw new PRRuntimeException("Invalid cipher text provided");
		} else {
			int prefixLength = getCipherPrefix(cipherText).length();
			int currentEncryptKeyHashLength = ByteBuffer.allocate(4).putInt(16).array().length;
			byte[] decodedBytes = Base64.decode(cipherText.substring(prefixLength));
			int length = decodedBytes.length;
			int Id = ByteBuffer.wrap(Arrays.copyOfRange(decodedBytes, 0, currentEncryptKeyHashLength)).getInt();
			String keyId = Id + "";
			decodedBytes = Arrays.copyOfRange(decodedBytes, currentEncryptKeyHashLength, length);
			DataKey key = getCustomerDataKey((String)keyStoreInfo.getKey(), keyId);
			PaddedBufferedBlockCipher cipher = getCipher(2, key);
			try {
				byte[] output = new byte[cipher.getOutputSize(decodedBytes.length)];
				int len1 = cipher.processBytes(decodedBytes, 0, decodedBytes.length, output, 0);
				int len2 = cipher.doFinal(output, len1);
				byte[] rawdata = new byte[len1 + len2];
				System.arraycopy(output, 0, rawdata, 0, rawdata.length);
				return new String(rawdata, "UTF-8");
			} catch (Exception var15) {
				throw new PRRuntimeException("An error occurred during decryption ", var15);
			}
		}
	}
 
	private static DataKey getCustomerDataKey(String keyMetadataType, String cdkId) {
		String pyEncryptedCDK= new String("rO0ABXNyAENjb20ucGVnYS5wZWdhcnVsZXMuZXhlYy5pbnRlcm5hbC5jcnlwdG8uZGF0YWVuY3J5 cHRpb24uS2V5RGF0YUJ5dGVzAAAAAAAAAAECAAJbAANtSVZ0AAJbQlsABG1LZXlxAH4AAXhwdXIA AltCrPMX+AYIVOACAAB4cAAAABBMNEheXy/2luYs7tHRzaHAdXEAfgADAAAAuAECAgB4VXwF8gWW W2PYQrdDM0nG8h9bJ/8AlmKeRXlGrab5UQkB9axvHYNwep9Hm8YvzYUd3AAAAH4wfAYJKoZIhvcN AQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDEawkLWFfOeM9QGyVAIBEIA7 qFz3qYQmalK0TzzoJceQCyKIw+G/lnjxS1ZP4EmRnX6AUFpR/QB8L3WzxO5jPODrD3+U8uTUdJR6gw8=");
		ByteArrayInputStream in = null;
		ObjectInputStream is = null;
		KeyDataBytes keyDataBytes = null;
		try {
				in = new ByteArrayInputStream(Base64.decode(pyEncryptedCDK));
				is = new ObjectInputStream(in);
				keyDataBytes = (KeyDataBytes)is.readObject();
		} catch (Exception e) {
			throw new PRRuntimeException("An error occurred during decryption ", e);
		
		}
		ByteBuffer encryptedCDK = ByteBuffer.wrap(keyDataBytes.getKeyBytes());
		AWSKMSCredential awskmsCredential = new AWSKMSCredential();
		String accessKeyID = "AKIAIPZLR5R5STICXPLA";
		awskmsCredential.setAccessKeyId(accessKeyID);
		String secretAccessKey = "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";
		awskmsCredential.setSecretKey(secretAccessKey);
		AWSKMSKeyMetadata awskmsKeyMetadata = new AWSKMSKeyMetadata();
		awskmsKeyMetadata.setMasterKeyId("arn:aws:kms:us-east-1:277616667829:key/b71df0c6-2570-4849-a6b9-0517a9fd4dce");
		awskmsKeyMetadata.setKeyRotationInterval(90);
		awskmsKeyMetadata.setKmsCredentials(awskmsCredential);
		awskmsKeyMetadata.setKeyStoreName("TestKeyStore");
		KMSKeyMetadata keyMetadata =  awskmsKeyMetadata;
		if (StringUtils.isNotBlank(keyMetadataType) && !keyMetadataType.equalsIgnoreCase(keyMetadata.getKeyMetadataType())) {
			//  keyMetadata = kmsManager.getKMSActiveKeyMetadata();
		}
		ByteBuffer plainTextKey = decryptEncryptedKey(keyMetadata, encryptedCDK);
		EncryptedDataKey encryptedDataKey = new EncryptedDataKey();
		encryptedDataKey.setEncryptedDataKey(keyDataBytes.getKeyBytes());
		encryptedDataKey.setIv(keyDataBytes.getIVBytes());
		byte[] iv = keyDataBytes.getIVBytes();
		DataKey dataKey = new DataKey(plainTextKey, iv, "v2.0");
		return dataKey;
	}

	private static ConcurrentLinkedHashMap<ByteBuffer, ByteBuffer> mCDKCache = (new Builder()).maximumWeightedCapacity(100L).build();
	
    private static ByteBuffer decryptEncryptedKey(KMSKeyMetadata kmsKeyMetadata, ByteBuffer encryptedDataKey) {
       ByteBuffer internalEncryptedCDK = (ByteBuffer)mCDKCache.get(encryptedDataKey);
       ByteBuffer cdkKey = null;
       if (internalEncryptedCDK != null) {
          byte[] cdk = InternalCryptography.getInstance().cryptographyOperation(internalEncryptedCDK.array(), 2, ThreadContainer.get());
 
          cdkKey = ByteBuffer.wrap(cdk);
 
       } else {
          KeyManagementService kmsInstance = KeyManagementServiceFactory.getKMSInstance(kmsKeyMetadata.getKeyMetadataType());
          cdkKey = kmsInstance.decrypt(encryptedDataKey, kmsKeyMetadata);
       }
       return cdkKey;
    }
 
	private static PaddedBufferedBlockCipher getCipher(int cipherMode, DataKey dataKey) {
		PaddedBufferedBlockCipher cipher = null;
		try {
			byte[] IV = dataKey.getIv();
			byte[] key = new byte[dataKey.getKey().remaining()];
			String cdkVersion = dataKey.getCDKVersion();
			if (StringUtils.isNotBlank(cdkVersion) && !cdkVersion.equalsIgnoreCase("v1.0")) {
			dataKey.getKey().get(key);
			dataKey.getKey().rewind();
			}
			KeyParameter kp = new KeyParameter(key);
			CipherParameters params = new ParametersWithIV(kp, IV);
			CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
			cipher = new PaddedBufferedBlockCipher(aes, new PKCS7Padding());
			switch(cipherMode) {
				case 1:
					cipher.init(true, params);
					break;
				case 2:
					cipher.init(false, params);
					break;
				default:
					throw new PRRuntimeException("Unsupported Cipher Mode");
			} 
		} catch (Exception var9) {
		}
		return cipher;
	}


	private static SimpleEntry<String, Boolean> isValidKeyStore(String cipherText) {
	String prefix = getCipherPrefix(cipherText);
	boolean isValid = false;
	String provider = "Invalid";      byte var6 = -1;      switch(prefix.hashCode()) {      case 12072641:         if (prefix.equals("\t{ak}")) {            var6 = 1;         }         break;      case 12075679:         if (prefix.equals("\t{dp}")) {            var6 = 4;         }         break;      case 12079709:         if (prefix.equals("\t{hv}")) {            var6 = 2;         }         break;      case 12086746:         if (prefix.equals("\t{pa}")) {            var6 = 0;         }         break;      case 12086932:         if (prefix.equals("\t{pg}")) {
			var6 = 3;
		}      }      switch(var6) {      case 0:
		isValid = true;
		provider = KMSType.AWS.toString();
		break;
	case 1:
		isValid = true;
		provider = KMSType.AZURE.toString();
		break;
	case 2:
		isValid = true;
		provider = KMSType.HASHICORP.toString();
		break;
	case 3:
		isValid = true;
		provider = KMSType.GCP.toString();
		break;
	case 4:
		isValid = true;
		provider = KMSType.CUSTOM_DATAPAGE.toString();
	}
	return new SimpleEntry(provider, isValid);
	}


	private static String getCipherPrefix(String cipherText) {
	String prefix = "";
	if (StringUtils.isNotBlank(cipherText)) {
		int prefixEndIndex = cipherText.indexOf("}");
		if (prefixEndIndex > 0) {
			prefix = cipherText.substring(0, prefixEndIndex + 1);
		}      }

	return prefix;
	}

}