const express = require("express");
const bodyParser = require("body-parser");
const { ClientSecretCredential } = require("@azure/identity");
const axios = require("axios");
const { CosmosClient } = require("@azure/cosmos");
const crypto = require("crypto");
const { execSync, exec } = require("child_process");
const fs = require("fs");
const AWS = require("aws-sdk");
const path = require("path");
const AdmZip = require("adm-zip");

require("dotenv").config();
const { ResourceManagementClient } = require("@azure/arm-resources");

function generateRandomString(length) {
  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString("hex")
    .slice(0, length);
}

const policyName = `policy-${generateRandomString(8)}`;
const displayName = "Policy Display Name";

const app = express();
app.use(bodyParser.json());

const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;
const tenantId = process.env.tenantId;
const subscriptionId = process.env.subscriptionId;
const endpoint = "https://iamneodev.documents.azure.com:443/";
const key =
  "LPc3MlGwYiyyFYMsWoxuFIAawCPV9fmfCPtfsaeeqDKRebeqalb9nX7DyP8F5BY1AmtaozGdkFDyACDbthGQTA==";
const databaseId = "db";
const containerId = "db";

// Function to create a new Azure AD user
async function createUser(displayName, mailNickname, password, accessToken) {
  const graphApiUrl = "https://graph.microsoft.com/v1.0/users";

  const headers = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  };

  const userData = {
    accountEnabled: true,
    displayName: displayName,
    mailNickname: mailNickname,
    userPrincipalName: `${mailNickname}@techdevopsiamneoaioutlook.onmicrosoft.com`,
    passwordProfile: {
      forceChangePasswordNextSignIn: false,
      password: password,
    },
  };

  const createUserResponse = await axios.post(graphApiUrl, userData, {
    headers,
  });

  console.log(
    `User ${createUserResponse.data.displayName} created successfully`
  );

  return createUserResponse.data;
}
function generateRandomPassword(length) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let password = "";

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    password += characters.charAt(randomIndex);
  }

  return password;
}

app.post("/create-user", async (req, res) => {
  try {
    const { testid, userid, schoolid } = req.body;

    // Connect to Cosmos DB and query for user with given email and password
    const cosmosClient = new CosmosClient({ endpoint, key });
    const { database } = await cosmosClient.databases.createIfNotExists({
      id: databaseId,
    });
    const { container } = await database.containers.createIfNotExists({
      id: containerId,
    });
    const querySpec = {
      query:
        "SELECT * FROM c WHERE c.testid = @testid AND c.userid = @userid AND c.schoolid = @schoolid",
      parameters: [
        { name: "@testid", value: testid },
        { name: "@userid", value: userid },
        { name: "@schoolid", value: schoolid },
      ],
    };
    const { resources } = await container.items.query(querySpec).fetchAll();

    if (resources.length === 0 || resources[0].issubmitted === true) {
      const userDisplayName = "User 1";
      const userPrefix = "coder";
      const userPassword = generateRandomPassword(10);
      // Generate a random number to append to the username
      const uuidv4 = require("uuid").v4;
      let randomNumberUser = uuidv4();
      randomNumberUser = randomNumberUser.slice(0, 6);
      const mailNickname = `${userPrefix}${randomNumberUser}`;

      // Get the access token for Microsoft Graph API
      const credential = new ClientSecretCredential(
        tenantId,
        clientId,
        clientSecret
      );
      const tokenResponse = await credential.getToken(
        "https://graph.microsoft.com/.default"
      );
      const accessToken = tokenResponse.token;

      // Create the user in Azure AD
      const createdUser = await createUser(
        userDisplayName,
        mailNickname,
        userPassword,
        accessToken
      );
      const upn = createdUser.userPrincipalName;
      const resourceGroupName = "rg" + mailNickname;

      const client = new ResourceManagementClient(credential, subscriptionId);
      await client.resourceGroups.createOrUpdate(resourceGroupName, {
        location: "eastus",
      });

      console.log(`Resource group ${resourceGroupName} created successfully`);

      exec(
        `az login --service-principal -u ${clientId} -p ${clientSecret} --tenant ${tenantId}`,
        async (err, stdOut, stdErr) => {
          if (err) {
            console.error("Error during authentication:", err);
            throw err;
          }
          console.log(
            "Authenticated with Azure AD using Service Principal credentials"
          );
          const assignRoleCommand = `az role assignment create --role "Contributor" --assignee ${upn} --resource-group ${resourceGroupName}`;

          exec(assignRoleCommand, (err, stdOut, stdErr) => {
            if (err) {
              console.error("Error assigning role to user:", err);
              throw err;
            }
            console.log(
              `Assigned "Contributor" role to ${upn} on resource group ${resourceGroupName}`
            );

            try {
              var uuid = require("uuid").v4;

              let directoryFullPath = uuid();
              directoryFullPath = directoryFullPath.slice(0, 8);
              fs.mkdirSync(directoryFullPath);
              console.log("Directory created successfully");

              AWS.config.update({
                accessKeyId: process.env.ACCESS_KEY_ID,
                secretAccessKey: process.env.SECRET_ACCESS_KEY,
                region: "us-east-1",
              });

              const s3 = new AWS.S3();
              const bucketName = "iamneo123";
              const fileKey = "policy123.zip";
              const getObjectParams = {
                Bucket: bucketName,
                Key: fileKey,
              };

              // Create a writable stream for saving the downloaded file
              const fileStream = fs.createWriteStream(
                path.join(directoryFullPath, fileKey)
              );

              // Download the file from S3 bucket
              const downloadFile = s3
                .getObject(getObjectParams)
                .createReadStream();

              // Handle the file download
              downloadFile.on("error", (err) => {
                console.error("Error downloading file:", err);
              });

              downloadFile.pipe(fileStream);

              // Handle the download completion
              fileStream.on("close", () => {
                console.log("File downloaded successfully!");

                // Save the file to the created folder
                const filePath = path.join(directoryFullPath, fileKey);
                fileStream.pipe(fs.createWriteStream(filePath));

                // Extract the downloaded zip file
                const zip = new AdmZip(filePath);
                zip.extractAllTo(directoryFullPath, true);

                const createPolicyDefinition = () => {
                  const description =
                    "This policy ensures that storage accounts with exposures to public networks are audited.";
                  const jsonFiles = fs
                    .readdirSync(directoryFullPath)
                    .filter((file) => file.endsWith(".json"));

                  if (jsonFiles.length > 0) {
                    const jsonFilePath = path.join(
                      directoryFullPath,
                      jsonFiles[0]
                    );
                    try {
                      execSync(
                        `az policy definition create --name '${policyName}' --display-name '${displayName}' --description '${description}' --rules '${jsonFilePath}' --mode All`
                      );
                      console.log("Policy definition created successfully.");
                    } catch (error) {
                      console.error(
                        "Error creating policy definition:",
                        error.message
                      );
                    }
                  } else {
                    console.error(
                      "No JSON file found in the extracted folder."
                    );
                  }
                };

                const assignPolicyToResourceGroup = () => {
                  try {
                    const definitionId = execSync(
                      `az policy definition show --name '${policyName}' --query 'id' --output tsv`
                    )
                      .toString()
                      .trim();
                    execSync(
                      `az policy assignment create --name '${policyName}-assignment' --scope '/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}' --policy '${definitionId}'`
                    );
                    console.log(
                      "Policy assigned to resource group successfully."
                    );
                    try {
                      const removeCommand = `rm -rf ${directoryFullPath}`;
                      execSync(removeCommand, (err, stdOut, stdErr) => {
                        if (err || stdErr) {
                          console.error('Error removing temporary directory:', err,stdErr);
                        } else {
                          if (fs.existsSync(directoryFullPath)) {
                            console.error('Error removing temporary directory: Directory still exists');
                          } else {
                            console.log('Temporary directory removed successfully');
                          }
                        }
                      });
                    } catch (error) {
                      console.error('Error removing temporary directory:', error);
                    }
                    const newUser = {
                      username: createdUser.userPrincipalName,
                      password: userPassword,
                      testid,
                      userid,
                      schoolid,
                      resourcegroupname: resourceGroupName,
                      policyname: policyName,
                      status: true,
                      issubmitted: false,
                    };
console.log(newUser,"<-------")
console.log(newUser.username)
                    // Insert the new user into the database
                    const { resource: createdItem } =
                      container.items.create(newUser);
                    console.log(
                      `User ${createdItem.username} inserted into the database`
                    );

                    res.status(200).json({
                      message: "User created successfully",
                      user: createdItem,
                    });
                  } catch (error) {
                    console.error(
                      "Error assigning policy to resource group:",
                      error.message
                    );
                    res.status(500).json({
                      message:
                        "An error occurred while assigning policy to resource group",
                    });
                  }
                };

                createPolicyDefinition();
                assignPolicyToResourceGroup();
              });
            } catch (error) {
              console.error("Error creating directory:", error);
              res.status(500).json({
                message: "An error occurred while creating the directory",
              });
            }
          });
        }
      );
    } else if (resources[0].issubmitted === false) {
      const { username, password } = resources[0];
      res.status(200).json({
        message: "User found",
        username,
        password,
      });
    } else {
      res.status(404).json({
        message: "No document found",
      });
    }
  } catch (error) {
    console.error("Error creating user:", error.message);
    res.status(500).json({
      message: "An error occurred while creating the user",
    });
  }
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
