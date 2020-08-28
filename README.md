# ForgeRock Access Management - Demo Key ID Provider

By default, AM generates a key ID (kid) for each public key exposed in the jwk_uri URI when AM is configured as an OAuth 2.0 authorization server.

For keys stored in a keystore secret store, you can customize how key ID values are determined by writing an implementation of the KeyStoreKeyIdProvider interface and configuring it in AM.

This is a sample implementation which calculates the Key ID based on a SHA1 hash of the JWK thumbprint for each key, according to RFC 7638.

## Build The Source Code

In order to build the project from the command line follow these steps:

### Prepare your Environment

You will need the following software to build the code.

```
Software               | Required Version
---------------------- | ----------------
Java Development Kit   | 1.8 and above
Maven                  | 3.1.0 and above
Git                    | 1.7.6 and above
```
The following environment variables should be set:

- `JAVA_HOME` - points to the location of the version of Java that Maven will use.
- `MAVEN_OPTS` - sets some options for the jvm when running Maven.

For example your environment variables might look something like this:

```
JAVA_HOME=/usr/jdk/jdk1.8.0_201
MAVEN_HOME=C:\Program Files\Apache_Maven_3.6.0
MAVEN_OPTS='-Xmx2g -Xms2g -XX:+CMSClassUnloadingEnabled -XX:MaxPermSize=512m'
```

### Getting the Code

If you want to run the code unmodified you can simply clone the repository:

```
git clone https://github.com/christian-brindley/DemoKeyIdProvider
```


### Building the Code

The build process and dependencies are managed by Maven. The first time you build the project, Maven will pull 
down all the dependencies and Maven plugins required by the build, which can take a longer time. 
Subsequent builds will be much faster!

```
cd DemoKeyIDProvider
mvn clean install
```

Maven builds the binary in `./target/`. The file name format is `am-demokeyidprovider-1.0.jar`  


### Adding the library to OpenAM war

+ Download and unzip the OpenAM.war from ForgeRock backstage: https://backstage.forgerock.com/downloads/browse/am/latest
```
$ mkdir ROOT && CD ROOT
$ jar -xf ~/Downloads/AM-6.5.2.war
```

+ Copy the newly generated jar file to /ROOT/WEB-INF/lib folder

```
$ cp ../target/am-demokeyidprovider-1.0.jar WEB-INF/lib
```

+ Rebuild the war file: 

```
$ jar -cf ../ROOT.war *
```

### Installing the key id provider

Deploy the updated WAR file, and follow the instructions to configure AM to use the new key id provider

  https://backstage.forgerock.com/docs/am/6.5/oidc1-guide/#customizing-kids

In brief, this involves setting the server advanced property ```org.forgerock.openam.secrets.keystore.keyid.provider``` to ```org.authdemo.keyidprovider.DemoKeyIdProvider```
