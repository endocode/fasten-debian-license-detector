package eu.fasten.analyzer.licensedetector;

import com.google.common.collect.Sets;
import eu.fasten.core.data.metadatadb.license.DetectedLicense;
import eu.fasten.core.data.metadatadb.license.DetectedLicenseSource;
import eu.fasten.core.data.metadatadb.license.DetectedLicenses;
import eu.fasten.core.plugins.KafkaPlugin;
import org.apache.maven.model.License;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.pf4j.Extension;
import org.pf4j.Plugin;
import org.pf4j.PluginWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class LicenseDetectorPlugin extends Plugin {

    public DebianLicenseDetectorPlugin(PluginWrapper wrapper) {
        super(wrapper);
    }

    @Extension
    public static class DebianLicenseDetector implements KafkaPlugin {

        private final Logger logger = LoggerFactory.getLogger(DebianLicenseDetector.class.getName());

        protected Exception pluginError = null;

        /**
         * The topic this plugin consumes.
         */
        protected String consumerTopic = "fasten.SyncC.out";

        /**
         * TODO
         */
        protected DetectedLicenses detectedLicenses = new DetectedLicenses();

        @Override
        public Optional<List<String>> consumeTopic() {
            return Optional.of(Collections.singletonList(consumerTopic));
        }

        @Override
        public void setTopic(String topicName) {
            this.consumerTopic = topicName;
        }

        /**
         * Resets the internal state of this plugin.
         */
        protected void reset() {
            pluginError = null;
            detectedLicenses = new DetectedLicenses();
        }

        @Override
        public void consume(String record) {
            try { // Fasten error-handling guidelines

                reset();

                logger.info("Debian license detector started.");
                // Retrieving the repo URL
                String repoUrl = extractRepoURL(record);
                // Retrieving the package name
                String packageName = extractPackageName(record);
                logger.info("The package to analyze is:"+packageName+".");
                // Retrieving the package version
                String packageVersion = extractPackageVersion(record);
                logger.info("The package version is:"+packageVersion+".");
                // Debian outbound license detection
                detectedLicenses.setOutbound(getDebianOutboundLicenses(packageName, packageVersion, repoUrl));
                if (detectedLicenses.getOutbound() == null || detectedLicenses.getOutbound().isEmpty()) {
                    logger.warn("No Debian outbound licenses were detected.");
                } else {
                    logger.info(
                            detectedLicenses.getOutbound().size() + " outbound license" +
                                    (detectedLicenses.getOutbound().size() == 1 ? "" : "s") + " detected: " +
                                    detectedLicenses.getOutbound()
                    );
                }

                // FROM HERE TO COMPLETELY REVIEW
                // Detecting inbound licenses by scanning the project
                String JSONFileWithLicensesInformationForFiles = analyzeProject(packageName,packageVersion);

                // Parsing the JSON created by the analyzeProject function
                JSONArray fileLicenses = parseScanResult(JSONFileWithLicensesInformationForFiles);
                if (fileLicenses != null && !fileLicenses.isEmpty()) {
                    detectedLicenses.addFiles(fileLicenses);
                } else {
                    logger.warn("The analyzer hasn't detected any licenses in " + JSONFileWithLicensesInformationForFiles + ".");
                }

            } catch (Exception e) { // Fasten error-handling guidelines
                logger.error(e.getMessage(), e.getCause());
                setPluginError(e);
            }
        }

        // this method first get the license from one of the copyrights files (copyright, license or readme), if
        // these files are not present try to retrieve the outbound license from github, using the repourl.
        /**
         * Retrieves the outbound license(s) of the input project.
         *
         * @param packageName the name of the package to be scanned.
         * @param packageVersion the version of the package to be scanned.
         * @return the set of detected outbound licenses.
         */
        protected Set<DetectedLicense> getDebianOutboundLicenses(String packageName, String packageVersion, String repoUrl) {

            try {
                // Retrieving the outbound license(s) from one of the copyright files (copyright, license or readme)
                // TODO passing also the path as SOURCE
                JSONObject FileAndPath = retrieveCopyrightFile(packageName,packageVersion)
                if (FileAndPath.getString("license")!= null){
                    String license = FileAndPath.getString("license");
                    return license;
                }


            } catch (FileNotFoundException | RuntimeException | XmlPullParserException e) {

                // In case retrieving the outbound license from the copights  files was not possible
                logger.warn(e.getMessage(), e.getCause()); // why wasn't it possible
                logger.info("Retrieving outbound license from GitHub...");
                if ((detectedLicenses.getOutbound() == null || detectedLicenses.getOutbound().isEmpty())
                        && repoUrl != null) {

                    // Retrieving licenses from the GitHub API
                    try {
                        DetectedLicense licenseFromGitHub = getDebianLicenseFromGitHub(repoUrl);
                        if (licenseFromGitHub != null) {
                            return Sets.newHashSet(licenseFromGitHub);
                        } else {
                            logger.warn("Couldn't retrieve the outbound license from GitHub.");
                        }
                    } catch (IllegalArgumentException | IOException ex) { // not a valid GitHub repo URL
                        logger.warn(e.getMessage(), e.getCause());
                    } catch (@SuppressWarnings({"TryWithIdenticalCatches", "RedundantSuppression"})
                            RuntimeException ex) {
                        logger.warn(e.getMessage(), e.getCause()); // could not contact GitHub API
                    }
                }
            }

            return Collections.emptySet();
        }

        // TODO
        /**
         * Retrieves the licenses declared in the files: `copyright`, `license`, `readme` .
         *
         * @param packageName the package name to be analyzed.
         * @param packageVersion the package version to be analyzed.
         * @return the detected licenses.
         * @throws XmlPullParserException in case the `pom.xml` file couldn't be parsed as an XML file.
         */
        protected Set<DetectedLicense> getLicensesFromCopyrightFile(String packageName, String packageVersion) throws XmlPullParserException {

            // Result
            List<License> licenses;

            // Maven `pom.xml` file parser
            MavenXpp3Reader reader = new MavenXpp3Reader();
            try (FileReader fileReader = new FileReader(pomFile)) {

                // Parsing and retrieving the `licenses` XML tag
                Model model = reader.read(fileReader);
                licenses = model.getLicenses();

                // If the pom file contains at least a license tag
                if (!licenses.isEmpty()) {

                    // Logging
                    logger.trace("Found " + licenses.size() + " outbound license" + (licenses.size() == 1 ? "" : "s") +
                            " in " + pomFile.getAbsolutePath() + ":");
                    for (int i = 0; i < licenses.size(); i++) {
                        logger.trace("License number " + i + ": " + licenses.get(i).getName());
                    }

                    // Returning the set of discovered licenses
                    Set<DetectedLicense> result = new HashSet<>(Collections.emptySet());
                    licenses.forEach(license -> result.add(new DetectedLicense(
                            license.getName(),
                            DetectedLicenseSource.LOCAL_POM)));

                    return result;
                }
            } catch (IOException e) {
                throw new RuntimeException("Pom file " + pomFile.getAbsolutePath() +
                        " exists but couldn't instantiate a FileReader object..", e.getCause());
            } catch (XmlPullParserException e) {
                throw new XmlPullParserException("Pom file " + pomFile.getAbsolutePath() +
                        " exists but couldn't be parsed as a Maven pom XML file: " + e.getMessage());
            }

            // No licenses were detected
            return Collections.emptySet();
        }

        /**
         * Retrieves the outbound license of a GitHub project using its API.
         *
         * @param repoUrl the repository URL whose license is of interest.
         * @return the outbound license retrieved from GitHub's API.
         * @throws IllegalArgumentException in case the repository is not hosted on GitHub.
         * @throws IOException              in case there was a problem contacting the GitHub API.
         */
        protected DetectedDebianLicense getDebianLicenseFromGitHub(String repoUrl)
                throws IllegalArgumentException, IOException {

            // Adding "https://" in case it's missing
            if (!Pattern.compile(Pattern.quote("http"), Pattern.CASE_INSENSITIVE).matcher(repoUrl).find()) {
                repoUrl = "https://" + repoUrl;
            }

            // Checking whether the repo URL is a valid URL or not
            URL parsedRepoUrl;
            try {
                parsedRepoUrl = new URL(repoUrl);
            } catch (MalformedURLException e) {
                throw new MalformedURLException("Repo URL " + repoUrl + " is not a valid URL: " + e.getMessage());
            }

            // Checking whether the repo is hosted on GitHub
            if (!Pattern.compile(Pattern.quote("github"), Pattern.CASE_INSENSITIVE).matcher(repoUrl).find()) {
                throw new IllegalArgumentException("Repo URL " + repoUrl + " is not hosted on GitHub.");
            }

            // Parsing the GitHub repo URL
            String path = parsedRepoUrl.getPath();
            String[] splitPath = path.split("/");
            if (splitPath.length < 3) { // should be: ["/", "owner", "repo"]
                throw new MalformedURLException(
                        "Repo URL " + repoUrl + " has no valid path: " + Arrays.toString(splitPath));
            }
            String owner = splitPath[1];
            String repo = splitPath[2].replaceAll(".git", "");
            logger.info("Retrieving outbound license from GitHub. Owner: " + owner + ", repo: " + repo + ".");

            // Result
            DebianDetectedLicense repoLicense;

            // Querying the GitHub API
            try {

                // Format: "https://api.github.com/repos/`owner`/`repo`/license"
                URL url = new URL("https://api.github.com/repos/" + owner + "/" + repo + "/license");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Accept", "application/json");
                if (conn.getResponseCode() != 200) {
                    throw new RuntimeException("HTTP query failed. Error code: " + conn.getResponseCode());
                }
                InputStreamReader in = new InputStreamReader(conn.getInputStream());
                BufferedReader br = new BufferedReader(in);
                String jsonOutput = br.lines().collect(Collectors.joining());

                // Retrieving the license SDPX ID
                var jsonOutputPayload = new JSONObject(jsonOutput);
                if (jsonOutputPayload.has("license")) {
                    jsonOutputPayload = jsonOutputPayload.getJSONObject("license");
                }
                repoLicense = new DetectedLicense(jsonOutputPayload.getString("spdx_id"), DetectedLicenseSource.GITHUB);

                conn.disconnect();
            } catch (ProtocolException e) {
                throw new ProtocolException(
                        "Couldn't set the GET method while retrieving an outbound license from GitHub: " +
                                e.getMessage());
            } catch (IOException e) {
                throw new IOException(
                        "Couldn't get data from the HTTP response returned by GitHub's API: " + e.getMessage(),
                        e.getCause());
            }

            return repoLicense;
        }

        /**
         * Retrieves the package version of the input record.
         *
         * @param record the input record containing the package version information.
         * @return the package version
         * @throws IllegalArgumentException in case the function couldn't find the package version.
         */
        protected String extractPackageVersion(String record) throws IllegalArgumentException {
            var payload = new JSONObject(record);
            if (payload.has("fasten.RepoCloner.out")) {
                payload = payload.getJSONObject("fasten.RepoCloner.out");
            }
            if (payload.has("payload")) {
                payload = payload.getJSONObject("payload");
            }
            String packageVersion = payload.getString("version");
            if (packageVersion == null) {
                throw new IllegalArgumentException("Invalid version information: missing version information.");
            }
            return packageVersion;
        }

        /**
         * Retrieves the package name of the input record.
         *
         * @param record the input record containing package information.
         * @return the package name.
         */
        protected String extractPackageName(String record) {
            var payload = new JSONObject(record);
            if (payload.has("fasten.RepoCloner.out")) {
                payload = payload.getJSONObject("fasten.RepoCloner.out");
            }
            if (payload.has("payload")) {
                payload = payload.getJSONObject("payload");
            }
            return payload.getString("artifactId");
        }

        /**
         * Retrieves the repository URL from the input record.
         *
         * @param record the input record containing repository information.
         * @return the input repository URL.
         */
        @Nullable
        protected String extractRepoURL(String record) {
            var payload = new JSONObject(record);
            if (payload.has("fasten.RepoCloner.out")) {
                payload = payload.getJSONObject("fasten.RepoCloner.out");
            }
            if (payload.has("payload")) {
                payload = payload.getJSONObject("payload");
            }
            return payload.getString("repoUrl");
        }

        /**
         * Retrieves the copyright file given a package name and the package version path.
         *
         * @param packageName the package name to be analyzed.
         * @param packageVersion the package version to be analyzed.
         */
        protected JSONObject retrieveCopyrightFile(String packageName, String packageVersion) {
            URL url = new URL("https://sources.debian.org/api/src/" + packageName + "/" + packageVersion + "/");
            JSONObject LicenseAndPath = new JSONObject();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("HTTP query failed. Error code: " + conn.getResponseCode());
            }
            InputStreamReader in = new InputStreamReader(conn.getInputStream());
            BufferedReader br = new BufferedReader(in);
            String jsonOutput = br.lines().collect(Collectors.joining());
            // searching for the copyright files in the JSON response
            var jsonOutputPayload = new JSONObject(jsonOutput);
            if (jsonOutputPayload.has("content")) {
                JSONArray array2 = jsonOutputPayload.getJSONArray("content");
                //Getting json objects inside array
                for (int i = 0; i < array2.length(); i++) {
                    JSONObject obj4 = array2.getJSONObject(i);
                    //Getting name and type of json objects inside array2
                    String name = obj4.getString("name");
                    String type = obj4.getString("type");
                    String copyright = "copyright";
                    String licenseStr = "license";
                    String readme = "readme";
                    String license = null;
                    System.out.println("The file name is : " + obj4.getString("name") + " Type of obj4 at index " + i + " is : " + obj4.getString("type"));
                    //Converting both the strings to lower case for case insensitive checking
                    if (name.toLowerCase().contains(copyright)) {
                        String checksum = RetrieveChecksum(name, packageName, packageVersion);
                        if (checksum != null) {
                            // the following String should be modified in a JSONObject, and then parsing the license key
                            JSONObject LicenseAndPath = RetrieveLicenseAndPath(checksum, packageName, packageVersion);
                            if (LicenseAndPath.getString("license")!= null){
                                license = LicenseAndPath.getString("license");
                            }
                            if (license != null) {
                                System.out.println("The license retrieved is: "+license);
                                return LicenseAndPath;
                            }
                        }
                    }
                    if (name.toLowerCase().contains(licenseStr)) {
                        String checksum = RetrieveChecksum(name, packageName, packageVersion);
                        if (checksum != null) {
                            JSONObject LicenseAndPath = RetrieveLicenseAndPath(checksum, packageName, packageVersion);
                            if (LicenseAndPath.getString("license")!= null){
                                license = LicenseAndPath.getString("license");
                            }
                            if (license != null) {
                                System.out.println("The license retrieved is: "+license);
                                return LicenseAndPath;
                            }
                        }
                    }
                    if (name.toLowerCase().contains(readme)) {
                        String checksum = RetrieveChecksum(name, packageName, packageVersion);
                        if (checksum != null) {
                            JSONObject LicenseAndPath = RetrieveLicenseAndPath(checksum, packageName, packageVersion);
                            if (LicenseAndPath.getString("license") != null) {
                                license = LicenseAndPath.getString("license");
                            }
                            if (license != null) {
                                System.out.println("The license retrieved is: " + license);
                                return LicenseAndPath;
                            }
                        }
                    }
                    //System.out.println(name.toLowerCase().contains(license));
                    //System.out.println(name.toLowerCase().contains(readme));
                }
            } else {
                System.out.println(" No contents key in this JSON");
                return licenseAndFilePath;
            }
        }

        // retrieve checksum for a given file
        protected String RetrieveChecksum(String fileName, String packageName, String packageVersion) throws IOException {
            URL url = new URL("https://sources.debian.org/api/src/" + packageName + "/" + packageVersion + "/" + "/" + fileName + "/");
            String checksum = null;
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("HTTP query failed. Error code: " + conn.getResponseCode());
            }
            InputStreamReader in = new InputStreamReader(conn.getInputStream());
            BufferedReader br = new BufferedReader(in);
            String jsonOutput = br.lines().collect(Collectors.joining());

            var jsonOutputPayload = new JSONObject(jsonOutput);
            if (jsonOutputPayload.has("checksum")) {
                checksum = jsonOutputPayload.getString("checksum");
            }
            return checksum;
        }

        // return a JSONObject with license and filePath of a given checksum: tested and it seems ok.
        protected JSONObject RetrieveLicenseAndPath(String checksum, String packageName, String packageVersion) throws IOException {
            URL url = new URL("https://sources.debian.org/copyright/api/sha256/?checksum=" + checksum + "&package=" + packageName);
            String license = null;
            String filePath = null;
            //initialize an empty JSONObject
            JSONObject licenseAndFilePath = new JSONObject();

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("HTTP query failed. Error code: " + conn.getResponseCode());
            }
            InputStreamReader in = new InputStreamReader(conn.getInputStream());
            BufferedReader br = new BufferedReader(in);
            String jsonOutput = br.lines().collect(Collectors.joining());
            var jsonOutputPayload = new JSONObject(jsonOutput);
            if (jsonOutputPayload.has("result")) {
                JSONObject obj1= jsonOutputPayload.getJSONObject("result");
                if (obj1.has("copyright")) {
                    JSONArray array1 = obj1.getJSONArray("copyright");
                    for (int i = 0; i < array1.length(); i++) {
                        JSONObject obj2 = array1.getJSONObject(i);
                        String version = obj2.getString("version");
                        if (version.equals(packageVersion)){
                            license = obj2.getString("license");
                            filePath = obj2.getString("path");
                            licenseAndFilePath.put("license", license);
                            licenseAndFilePath.put("path", filePath);
                        }
                    }
                }
            }
            return licenseAndFilePath;
        }
        /**
         * Analyze a Debian repository looking for license at the file level.
         *
         * @param packageName the package name to be analyzed.
         * @param packageVersion the package version to be analyzed.
         * @return the URL where the license retrieval at the file level started.
         * @throws InterruptedException in case this function couldn't wait for the analysis to complete.
         * @throws RuntimeException     in case the URL of the package name and version doesn't exist.
         */
        protected String analyzeProject(String packageName, String packageVersion) throws InterruptedException, RuntimeException {
            JSONArray DetectedFileLicenses = new JSONArray();
            // Where is the result stored
            String retrieveLicensesInformationForFiles = null; //JSON name
                    // TODO
            // Start analyzing
            logger.info("Retrieving license information at the file level for: " + packageName + "; version: "+ packageVersion +" .");
            URL url = new URL("https://sources.debian.org/api/src/" + packageName + "/" + packageVersion + "/");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("HTTP query failed. Error code: " + conn.getResponseCode());
            }
            InputStreamReader in = new InputStreamReader(conn.getInputStream());
            BufferedReader br = new BufferedReader(in);
            String jsonOutput = br.lines().collect(Collectors.joining());
            // searching for the copyright files in the JSON response
            var jsonOutputPayload = new JSONObject(jsonOutput);

            JSONArray JSONFilesLicenses = AnalyzeDirectory(jsonOutputPayload, packageName, packageVersion);
            System.out.print(JSONFilesLicenses);

            logger.info("Analysis for " + packageName + " version: "+ packageVersion +" completed.");

            return retrieveLicensesInformationForFiles;
        }

        // Loop through files and insert path and license into a JSONArray
        protected JSONArray LoopThroughFiles(JSONArray JSONFiles) throws IOException {
            JSONArray LicenseAndPathFiles = new JSONArray();
            for (int j = 0; j < JSONFiles.length(); j++) {
                JSONObject obj = JSONFiles.getJSONObject(j);
                System.out.println(obj);
                if (obj.has("path")){
                    String checksum = RetrieveChecksumWithPath(obj.getString("path"));
                    System.out.println(checksum);
                    if (checksum != null) {
                        JSONObject LicenseAndPath = RetrieveLicenseAndPath(checksum, obj.getString("packageName"), obj.getString("packageVersion"));
                        System.out.println(LicenseAndPath);
                        LicenseAndPathFiles.put(LicenseAndPath);
                        //DetectedFileLicenses.put(LicenseAndPath.valueToString());
                    }
                }
            }
            return LicenseAndPathFiles;
        }

        protected JSONObject GetDirectoryJSON(String path) throws InterruptedException, RuntimeException, IOException {
            JSONObject JSONDirectory = new JSONObject();
            URL url = new URL("https://sources.debian.org/api/src/"+path+"/");
            System.out.println(url);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("HTTP query failed. Error code: " + conn.getResponseCode());
            }
            InputStreamReader in = new InputStreamReader(conn.getInputStream());
            BufferedReader br = new BufferedReader(in);
            String jsonOutput = br.lines().collect(Collectors.joining());
            // searching for the copyright files in the JSON response
            JSONDirectory = new JSONObject(jsonOutput);
            return JSONDirectory;
        }

        protected JSONArray AnalyzeDirectory(JSONObject JSONDirectoryPayload, String packageName, String packageVersion) throws IOException, InterruptedException, TimeoutException {
            JSONArray JSONFilesLicenses = new JSONArray();
            if (JSONDirectoryPayload.has("content")) {
                JSONArray array = JSONDirectoryPayload.getJSONArray("content");
                //System.out.println(array);
                JSONArray JSONFiles = new JSONArray();
                for (int i = 0; i < array.length(); i++) {
                    JSONObject obj = array.getJSONObject(i);
                    //Getting name and type of json objects inside array2
                    String name = obj.getString("name");
                    String type = obj.getString("type");
                    String FilePath = JSONDirectoryPayload.getString("path");
                    //System.out.println(FilePath);
                    if (type.equals("file")) {
                        FilePath = FilePath+"/"+name;
                        obj.put("path",FilePath);
                        obj.put("packageName",packageName);
                        obj.put("packageVersion",packageVersion);
                        //System.out.println(obj);
                        JSONFiles.put(obj);
                    }
                }
                System.out.println(JSONFiles);
                JSONFilesLicenses.put(LoopThroughFiles(JSONFiles));
                System.out.print(JSONFilesLicenses);
                // to add the JSONObject to DetectedLicenses

                for (int j = 0; j < array.length(); j++) {
                    JSONObject obj2 = array.getJSONObject(j);
                    //Getting name and type of json objects inside array2
                    String nameDir = obj2.getString("name");
                    String typeDir = obj2.getString("type");
                    String path = JSONDirectoryPayload.getString("path");
                    if (typeDir.equals("directory")){
                        path = path +"/"+nameDir;
                        System.out.println(path);
                        JSONObject JSONDirectory = GetDirectoryJSON(path);
                        JSONFilesLicenses.put(AnalyzeDirectory(JSONDirectory,packageName,packageVersion));
                        System.out.println(JSONDirectory);
                    }
                }
            }
            return JSONFilesLicenses;
        }

        private static String RetrieveChecksumWithPath(String path) throws IOException {
            URL url = new URL("https://sources.debian.org/api/src/" +path + "/");
            String checksum = null;
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("HTTP query failed. Error code: " + conn.getResponseCode());
            }
            InputStreamReader in = new InputStreamReader(conn.getInputStream());
            BufferedReader br = new BufferedReader(in);
            String jsonOutput = br.lines().collect(Collectors.joining());

            var jsonOutputPayload = new JSONObject(jsonOutput);
            if (jsonOutputPayload.has("checksum")) {
                checksum = jsonOutputPayload.getString("checksum");
            }
            return checksum;
        }

        /**
         * Parses the scan result file and returns file licenses.
         *
         * @param scanResultPath the path of the file containing the scan results.
         * @return the list of licenses that have been detected by scanning files.
         * @throws IOException   in case the JSON scan result couldn't be read.
         * @throws JSONException in case the root object of the JSON scan result couldn't have been retrieved.
         */
        protected JSONArray parseScanResult(String scanResultPath) throws IOException, JSONException {

            try {
                // Retrieving the root element of the scan result file
                JSONObject root = new JSONObject(Files.readString(Paths.get(scanResultPath)));
                if (root.isEmpty()) {
                    throw new JSONException("Couldn't retrieve the root object of the JSON scan result file " +
                            "at " + scanResultPath + ".");
                }

                // Returning file licenses
                if (root.has("files") && !root.isNull("files")) {
                    return root.getJSONArray("files");
                }
            } catch (IOException e) {
                throw new IOException("Couldn't read the JSON scan result file at " + scanResultPath +
                        ": " + e.getMessage(), e.getCause());
            }

            // In case nothing could have been found
            return null;
        }

        @Override
        public Optional<String> produce() {
            if (detectedLicenses == null ||
                    (detectedLicenses.getOutbound().isEmpty() && detectedLicenses.getFiles().isEmpty())
            ) {
                return Optional.empty();
            } else {
                return Optional.of(new JSONObject(detectedLicenses).toString());
            }
        }

        @Override
        public String getOutputPath() {
            return null; // FIXME
        }

        @Override
        public String name() {
            return "Debian License Detector Plugin";
        }

        @Override
        public String description() {
            return "Detects licenses at the file level";
        }

        @Override
        public String version() {
            return "0.1.0";
        }

        @Override
        public void start() {
        }

        @Override
        public void stop() {
        }

        @Override
        public Exception getPluginError() {
            return this.pluginError;
        }

        public void setPluginError(Exception throwable) {
            this.pluginError = throwable;
        }

        @Override
        public void freeResource() {
        }

        @Override
        public long getMaxConsumeTimeout() {
            return 30 * 60 * 1000; // 30 minutes
        }
    }
}
