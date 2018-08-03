/*
 * 
 * SHA-1 algorithm taken from -> https://en.wikipedia.org/wiki/SHA-1#Examples_and_pseudocode
 * SHA-2 algorithm taken from -> https://en.wikipedia.org/wiki/SHA-2#Pseudocode
 * 
 */

package secure.hash.algorithm;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Scanner;

public class SecureHashAlgorithm {
	
	private byte family, dataUnit;			// dataUnit is the size in bytes...
	private long[] inputSchedule;
	private long[][] bufferMatrix;		// buffer where the hash values will be stored...
	
	// static variables are declared below...
	private static final byte NUMBER_OF_FAMILIES = 2;		// total number of SHA families implemented in this class... needs to be updated with the code...
	public static final byte SHA_1 = 0, SHA_2 = 1;
	private static long[][] initialHashValues, roundConstants;		// index[0] for SHA-1 and index[1] for SHA-2
	
	private static Properties[] properties;
	private static final Object mutex = new Object();		// mutex for thread synchronization...
	
	public SecureHashAlgorithm(byte family) throws Exception {
		switch (family) {
		case SHA_1:
			dataUnit = Integer.SIZE / Byte.SIZE;
			
			break;
		case SHA_2:
			dataUnit = Long.SIZE / Byte.SIZE;
			
			break;
		default:
			throw new Exception("invalid SHA family provided as parameter");
		}
		
		this.family = family;
		
		synchronized (mutex) {
			if (properties == null) {
				properties = new Properties[NUMBER_OF_FAMILIES];
			}
			
			if (properties[this.family] == null) {
				properties[this.family] = new Properties(this.family);
			}
		}
		
		inputSchedule = new long[properties[this.family].getNumberOfRounds()];
		bufferMatrix = new long[properties[this.family].getBufferMatrixRows()][properties[this.family].getNumberOfInitialHashValues()];
		
		loadInitialHashValues();
		loadRoundConstants();
	}
	
	private void loadInitialHashValues() throws Exception {
		if (initialHashValues != null && initialHashValues[family].length != 0) {		// if array is already initialized, no need to execute this method...
			return;
		}
		
		synchronized (mutex) {
			if (initialHashValues == null) {
				initialHashValues = new long[NUMBER_OF_FAMILIES][0];
			}
			
			initialHashValues[family] = new long[properties[family].getNumberOfInitialHashValues()];
			
			Scanner scanner = new Scanner(this.getClass().getResourceAsStream("/data/initial-hash-values.SHA-" + (family + 1)));
			
			for (int i = 0; i < initialHashValues[family].length && scanner.hasNextLine(); i++) {
				initialHashValues[family][i] = new BigInteger(scanner.nextLine().trim(), properties[family].getNumberBaseOfData()).longValue();
			}
			
			scanner.close();
		}
	}
	
	private void loadRoundConstants() throws Exception {
		if (roundConstants != null && roundConstants[family].length != 0) {		// if array is already initialized, no need to execute this method...
			return;
		}
		
		synchronized (mutex) {
			if (roundConstants == null) {
				roundConstants = new long[NUMBER_OF_FAMILIES][0];
			}
			
			int counter = 0;
			
			roundConstants[family] = new long[properties[family].getNumberOfRoundConstants()];		// 4 round constants...
			
			Scanner scanner = new Scanner(this.getClass().getResourceAsStream("/data/round-constants.SHA-" + (family + 1)));
			
			while (scanner.hasNextLine()) {
				String[] roundConstants = scanner.nextLine().split(",");
				
				for (int i = 0; i < roundConstants.length && counter < SecureHashAlgorithm.roundConstants[family].length; i++, counter++) {
					SecureHashAlgorithm.roundConstants[family][counter] = new BigInteger(roundConstants[i].trim(), properties[family].getNumberBaseOfData()).longValue();
				}
			}
			
			scanner.close();
		}
	}
	
	private void initializeBufferMatrix() {
		for (int i = 0; i < bufferMatrix.length; i++) {		// copying initialHashValues to bufferMatrix...
			System.arraycopy(initialHashValues[family], 0, bufferMatrix[i], 0, initialHashValues[family].length);		// copying hash values to buffer...
		}
	}
	
	/*
	 * 
	 * for SHA-2
	 * 
	 */
	private long sigmaInputScheduleGeneration(int flag, long value) {
		if (flag == 0) {
			return Long.rotateRight(value, 1) ^ Long.rotateRight(value, 8) ^ (value >>> 7);
		}
		
		return Long.rotateRight(value, 19) ^ Long.rotateRight(value, 61) ^ (value >>> 6);
	}
	
	private void generateInputSchedule(byte[] inputBlock) {		// message schedule is generated here...
		byte inputBlockLength = (byte)(properties[family].getBlockSize() / dataUnit);		// inputBlockLength in long...
		
		for (int i = 0; i < inputBlockLength; i++) {
			inputSchedule[i] = toDataUnit(inputBlock, i * dataUnit);		// first (inputBlocks[0].length = 16) values will be directly copied...
		}
		
		for (int i = inputBlockLength; i < inputSchedule.length; i++) {
			if (family == SHA_1) {		// for SHA-1
				inputSchedule[i] = Integer.rotateLeft((int)inputSchedule[i - 3] ^ (int)inputSchedule[i - 8] ^
						(int)inputSchedule[i - 14] ^ (int)inputSchedule[i - 16], 1);
			}
			else {			// for SHA-2
				inputSchedule[i] = sigmaInputScheduleGeneration(1, inputSchedule[i - 2]) + inputSchedule[i - 7] +
						sigmaInputScheduleGeneration(0, inputSchedule[i - 15]) + inputSchedule[i - 16];
			}
		}
	}
	
	private long sigmaCompression(int flag, long value) {
		if (flag == 0) {
			return Long.rotateRight(value, 28) ^ Long.rotateRight(value, 34) ^ Long.rotateRight(value, 39);
		}
		
		return Long.rotateRight(value, 14) ^ Long.rotateRight(value, 18) ^ Long.rotateRight(value, 41);
	}
	
	/*
	 * 
	 * calculates hash of the inputBlock with the
	 * already existing data of the bufferMatrix
	 * 
	 */
	private void calculateHash(byte[] inputBlock) {
		int i;
		
		generateInputSchedule(inputBlock);		// inputSchedule is generated here...
		
		for (i = 0; i < properties[family].getNumberOfRounds(); i++) {		// 80 rounds of compression...
			if (family == SHA_1) {
				int j, k, temporary;			// 'j' is the index of round constant...
				
				if (i >= 0 && i <= 19) {
					j = 0;
					k = ((int)bufferMatrix[1][1] & (int)bufferMatrix[1][2]) | (~(int)bufferMatrix[1][1] & (int)bufferMatrix[1][3]);
				}
				else if (i >= 20 && i <= 39) {
					j = 1;
					k = (int)bufferMatrix[1][1] ^ (int)bufferMatrix[1][2] ^ (int)bufferMatrix[1][3];
				}
				else if (i >= 40 && i <= 59) {
					j = 2;
					k = ((int)bufferMatrix[1][1] & (int)bufferMatrix[1][2]) | ((int)bufferMatrix[1][1] & (int)bufferMatrix[1][3]) | ((int)bufferMatrix[1][2] & (int)bufferMatrix[1][3]);
				}
				else {
					j = 3;
					k = (int)bufferMatrix[1][1] ^ (int)bufferMatrix[1][2] ^ (int)bufferMatrix[1][3];
				}
				
		        temporary = Integer.rotateLeft((int)bufferMatrix[1][0], 5) + k + (int)bufferMatrix[1][4] + (int)roundConstants[family][j] + (int)inputSchedule[i];
		        bufferMatrix[1][4] = (int)bufferMatrix[1][3];
		        bufferMatrix[1][3] = (int)bufferMatrix[1][2];
		        bufferMatrix[1][2] = Integer.rotateLeft((int)bufferMatrix[1][1], 30);
		        bufferMatrix[1][1] = (int)bufferMatrix[1][0];
		        bufferMatrix[1][0] = (int)temporary;
			}
			else {					// for SHA-2
				long[] temporaries = new long[properties[family].getBufferMatrixRows()];		// we will need two temporary variables...
				
				for (i = 0; i < properties[family].getNumberOfRounds(); i++) {		// 80 rounds of compression...
					temporaries[0] = bufferMatrix[1][7] + sigmaCompression(1, bufferMatrix[1][4]) +
							((bufferMatrix[1][4] & bufferMatrix[1][5]) ^ (~bufferMatrix[1][4] & bufferMatrix[1][6])) + roundConstants[family][i] + inputSchedule[i];
					temporaries[1] = sigmaCompression(0, bufferMatrix[1][0]) +
							((bufferMatrix[1][0] & bufferMatrix[1][1]) ^ (bufferMatrix[1][0] & bufferMatrix[1][2]) ^ (bufferMatrix[1][1] & bufferMatrix[1][2]));
					
					bufferMatrix[1][7] = bufferMatrix[1][6];		// bufferMatrix[1] is basically 'a' to 'h'...
					bufferMatrix[1][6] = bufferMatrix[1][5];
					bufferMatrix[1][5] = bufferMatrix[1][4];
					bufferMatrix[1][4] = bufferMatrix[1][3] + temporaries[0];
					bufferMatrix[1][3] = bufferMatrix[1][2];
					bufferMatrix[1][2] = bufferMatrix[1][1];
					bufferMatrix[1][1] = bufferMatrix[1][0];
					bufferMatrix[1][0] = temporaries[0] + temporaries[1];
				}
			}
		}
		
		for (i = 0; i < bufferMatrix[0].length; i++) {
			if (family == SHA_1) {
				bufferMatrix[0][i] = (int)bufferMatrix[0][i] + (int)bufferMatrix[1][i];
			}
			else {
				bufferMatrix[0][i] = bufferMatrix[1][i] + bufferMatrix[0][i];
			}
			
			bufferMatrix[1][i] = bufferMatrix[0][i];
		}
	}
	
	private long calculateNumberOfBlocks(long inputLength) {		// original input length...
		long paddedLength = inputLength + 1;		// +1 for '1' bit added...
		
		while (paddedLength % properties[family].getBlockSize() != properties[family].getInputBytesInEachBlock() + 1) {		// +1 for '1' bit added with input...
			paddedLength++;
		}
		
		paddedLength += properties[family].getMaximumLengthBytes();
		
		return paddedLength / properties[family].getBlockSize();		// in bytes...
	}
	
	public String generateHash(byte[] input) {
		byte[] inputBlock = new byte[properties[family].getBlockSize()],		// 512 bits = 64 bytes of block...
				inputLengthInBytes = BigInteger.valueOf(input.length * Byte.SIZE).toByteArray();		// total input length in bytes...
		int bytesRead = 0;
		long numberOfBlocks = calculateNumberOfBlocks(input.length);
		
		initializeBufferMatrix();
		
		for (int i = 0; i < numberOfBlocks; i++) {
			for (int j = 0; j < inputBlock.length; j++, bytesRead++) {
				if (bytesRead < input.length) {
					inputBlock[j] = input[bytesRead];
				}
				else if (bytesRead == input.length) {
					inputBlock[j] = (byte)(Byte.MAX_VALUE + 1);		// adding bit '1'...
				}
				else {
					inputBlock[j] = 0;
				}
			}
			
			for (int j = inputLengthInBytes.length; i == numberOfBlocks - 1 && j > 0; j--) {		// appending length in the end...
				inputBlock[inputBlock.length - j] = inputLengthInBytes[inputLengthInBytes.length - j];
			}
			
			calculateHash(inputBlock);
		}
		
		return toString();
	}
	
	public String generateHash(String input) {
		return generateHash(input.getBytes());
	}
	
	public String generateHash(File inputFile) throws Exception {
		byte[] buffer = new byte[properties[family].getBlockSize()];
		int bytesRead = 0;
		
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		
		while ((bytesRead = fileInputStream.read(buffer, 0, buffer.length)) > 0) {
			byteArrayOutputStream.write(buffer, 0, bytesRead);
			byteArrayOutputStream.flush();
		}
		
		fileInputStream.close();
		
		String hash = generateHash(byteArrayOutputStream.toByteArray());
		
		byteArrayOutputStream.close();
		
		return hash;
	}
	
	/*
	 * converts byte array to long...
	 */
	private long toDataUnit(byte[] input, int offset) {
		ByteBuffer byteBuffer = ByteBuffer.wrap(input, offset, dataUnit);
		
		if (family == SHA_1) {
			return byteBuffer.getInt();
		}
		else {
			return byteBuffer.getLong();
		}
	}
	
	/*
	 * generates hex-string from the calculated hash stored in bufferMatrix[0]...
	 */
	@Override
	public String toString() {
		int desiredFormattedStringLength = dataUnit * 2;		// multiple of 2 as hex string is 2 characters per data...
		
		String format = "%016x";			// for SHA-2
		
		if (family == SHA_1) {			// for SHA-1
			format = "%16x";
		}
		
		StringBuilder stringBuilder = new StringBuilder(properties[family].getBlockSize());
		
		for (int i = 0; i < properties[family].getNumberOfInitialHashValues(); i++) {
			String formattedString = String.format(format, bufferMatrix[0][i]);
			
			if (formattedString.length() > desiredFormattedStringLength) {
				formattedString = formattedString.substring(desiredFormattedStringLength);		// taking the second half of the string...
			}
			
			stringBuilder.append(formattedString);
		}
		
		return stringBuilder.toString();
	}
	
}