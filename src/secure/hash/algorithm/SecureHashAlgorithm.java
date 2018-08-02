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
	
	private byte WORD_SIZE;			// size of long variable in bytes...
	private long[] inputSchedule, initialHashValues, roundConstants;
	private long[][] bufferMatrix;		// buffer where the hash values will be stored...
	
	private String family;
	private Properties properties;
	
	// static variables are declared below...
	private static final String[] FAMILIES = { "SHA-1", "SHA-2" };
	
	public SecureHashAlgorithm(String family) throws Exception {
		if (family.equals(FAMILIES[0])) {
			WORD_SIZE = Integer.SIZE / Byte.SIZE;
		}
		else if (family.equals(FAMILIES[1])) {
			WORD_SIZE = Long.SIZE / Byte.SIZE;
		}
		else {
			throw new Exception("please provide 'SHA-1' or 'SHA-2' without quotes as parameter");
		}
		
		this.family = family;
		
		if (properties == null) {
			properties = new Properties(this.family);		// data directory -> ..//data//two//...
		}
		
		inputSchedule = new long[properties.getNumberOfRounds()];
		bufferMatrix = new long[properties.getBufferMatrixRows()][properties.getNumberOfInitialHashValues()];
		
		loadInitialHashValues();
		loadRoundConstants();
	}
	
	private void loadInitialHashValues() throws Exception {
		if (initialHashValues != null) {		// if array is already initialized, no need to execute this method...
			return;
		}
		
		initialHashValues = new long[properties.getNumberOfInitialHashValues()];
		
		Scanner scanner = new Scanner(this.getClass().getResourceAsStream("/data/initial-hash-values." + family));
		
		for (int i = 0; i < initialHashValues.length && scanner.hasNextLine(); i++) {
			initialHashValues[i] = new BigInteger(scanner.nextLine().trim(), properties.getNumberBaseOfData()).longValue();
		}
		
		scanner.close();
	}
	
	private void loadRoundConstants() throws Exception {
		if (roundConstants != null) {		// if array is already initialized, no need to execute this method...
			return;
		}
		
		int counter = 0;
		
		roundConstants = new long[properties.getNumberOfRoundConstants()];		// 4 round constants...
		
		Scanner scanner = new Scanner(this.getClass().getResourceAsStream("/data/round-constants." + family));
		
		while (scanner.hasNextLine()) {
			String[] roundConstants = scanner.nextLine().split(",");
			
			for (int i = 0; i < roundConstants.length && counter < this.roundConstants.length; i++, counter++) {
				this.roundConstants[counter] = new BigInteger(roundConstants[i].trim(), properties.getNumberBaseOfData()).longValue();
			}
		}
		
		scanner.close();
	}
	
	private void initializeBufferMatrix() {
		for (int i = 0; i < bufferMatrix.length; i++) {		// copying initialHashValues to bufferMatrix...
			System.arraycopy(initialHashValues, 0, bufferMatrix[i], 0, initialHashValues.length);		// copying hash values to buffer...
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
		byte inputBlockLength = (byte)(properties.getBlockSize() / WORD_SIZE);		// inputBlockLength in long...
		
		for (int i = 0; i < inputBlockLength; i++) {
			inputSchedule[i] = toWord(inputBlock, i * WORD_SIZE);		// first (inputBlocks[0].length = 16) values will be directly copied...
		}
		
		for (int i = inputBlockLength; i < inputSchedule.length; i++) {
			if (family.equals(FAMILIES[0])) {		// for SHA-1
				inputSchedule[i] = Integer.rotateLeft((int)(inputSchedule[i - 3] ^ inputSchedule[i - 8] ^
						inputSchedule[i - 14] ^ inputSchedule[i - 16]), 1);
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
		
		if (family.equals(FAMILIES[0])) {		// for SHA-1
			int j, temporary;			// 'j' is the index of round constant...
			long k;
			
			for (i = 0; i < properties.getNumberOfRounds(); i++) {		// 80 rounds of compression...
				if (i >= 0 && i <= 19) {
					j = 0;
					k = (bufferMatrix[1][1] & bufferMatrix[1][2]) | (~bufferMatrix[1][1] & bufferMatrix[1][3]);
				}
				else if (i >= 20 && i <= 39) {
					j = 1;
					k = bufferMatrix[1][1] ^ bufferMatrix[1][2] ^ bufferMatrix[1][3];
				}
				else if (i >= 40 && i <= 59) {
					j = 2;
					k = (bufferMatrix[1][1] & bufferMatrix[1][2]) | (bufferMatrix[1][1] & bufferMatrix[1][3]) | (bufferMatrix[1][2] & bufferMatrix[1][3]);
				}
				else {
					j = 3;
					k = bufferMatrix[1][1] ^ bufferMatrix[1][2] ^ bufferMatrix[1][3];
				}
				
		        temporary = (int)(Integer.rotateLeft((int)bufferMatrix[1][0], 5) + k + bufferMatrix[1][4] + roundConstants[j] + inputSchedule[i]);
		        bufferMatrix[1][4] = bufferMatrix[1][3];
		        bufferMatrix[1][3] = bufferMatrix[1][2];
		        bufferMatrix[1][2] = Integer.rotateLeft((int)bufferMatrix[1][1], 30);
		        bufferMatrix[1][1] = bufferMatrix[1][0];
		        bufferMatrix[1][0] = temporary;
			}
			
			for (i = 0; i < bufferMatrix[0].length; i++) {
				bufferMatrix[0][i] += bufferMatrix[1][i];
				bufferMatrix[1][i] = bufferMatrix[0][i];
			}
		}
		else {					// for SHA-2
			long[] temporaries = new long[properties.getBufferMatrixRows()];		// we will need two temporary variables...
			
			for (i = 0; i < properties.getNumberOfRounds(); i++) {		// 80 rounds of compression...
				temporaries[0] = bufferMatrix[1][7] + sigmaCompression(1, bufferMatrix[1][4]) +
						((bufferMatrix[1][4] & bufferMatrix[1][5]) ^ (~bufferMatrix[1][4] & bufferMatrix[1][6])) + roundConstants[i] + inputSchedule[i];
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
			
			for (i = 0; i < bufferMatrix[0].length; i++) {
				bufferMatrix[0][i] = bufferMatrix[1][i] + bufferMatrix[0][i];
				bufferMatrix[1][i] = bufferMatrix[0][i];
			}
		}
	}
	
	private long calculateNumberOfBlocks(long inputLength) {		// original input length...
		long paddedLength = inputLength + 1;		// +1 for '1' bit added...
		
		while (paddedLength % properties.getBlockSize() != properties.getInputBytesInEachBlock() + 1) {		// +1 for '1' bit added with input...
			paddedLength++;
		}
		
		paddedLength += 16;
		
		return paddedLength / properties.getBlockSize();		// in bytes...
	}
	
	public String generateHash(byte[] input) {
		byte[] inputBlock = new byte[properties.getBlockSize()],		// 512 bits = 64 bytes of block...
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
		byte[] buffer = new byte[properties.getBlockSize()];
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
	private long toWord(byte[] input, int offset) {
		ByteBuffer byteBuffer = ByteBuffer.wrap(input, offset, WORD_SIZE);
		
		if (family.equals(FAMILIES[0])) {
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
		StringBuilder stringBuilder = new StringBuilder(properties.getBlockSize());
		
		for (int i = 0; i < properties.getNumberOfInitialHashValues(); i++) {
			String format = "%016x";			// for SHA-2
			
			if (family.equals(FAMILIES[0])) {			// for SHA-1
				format = "%16x";
			}
			
			stringBuilder.append(String.format(format, bufferMatrix[0][i]).trim());
		}
		
		return stringBuilder.toString();
	}
	
}