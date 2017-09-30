# S-DES

Simple, yet efficient, S-DES implementation in java that supports stream and string encryption.

S-DES (Simplified Data Encryption Standard) - is an educational rather than a secure symmetric encryption algorithm. It has similar properties and structure 
to DES with much smaller parameters.

### Installing

You can simply copy-paste SDES implementation to your project from  `SDES/src/main/java/cryptography/SDES.java`

Alternatively, you can build a .jar file and use it as a library:
1. `cd` into the desired directory and clone the project: `git clone https://github.com/Marakaido/SDES.git`.
2. Build the project:
   `chmod +x ./gradlew & ./gradlew build`
3. If successfull, .jar can be found at `SDES/build/libs`.
   Test summary is located at `SDES/build/reports/tests/test/index.html`.
4. Add the .jar file to your project's classpath 

## Usage

### Strings
```
int key = 0b0100011011;
String plainText = "plain text";

// Encrypt plain text
String cypherText = SDES.encrypt(plainText, key);

// Decrypt cypher text
String decypheredText = SDES.decrypt(cypherText, key);
```


### Streams
```
int key = 0b0100011011;
InputStream in = new BufferedInputStream(Files.newInputStream(Paths.get("data.txt")));
OutputStream out = new BufferedOutputStream(Files.newOutputStream(Paths.get("encrypted.txt")));

// Encrypt
SDES.encrypt(in, out, key);

// Decrypt (for demonstration purposes, we use the same streams)
SDES.decrypt(in, out, key);
```

## Running the tests

To run the tests: `./gradlew test`

Test summary is located at `SDES/build/reports/tests/test/index.html`

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
