# Use one OAuth project with two Desktop clients

Use one Google Cloud project for the Gmail Local Integration, with distinct Desktop OAuth client profiles for the Retrieval Grant and Transmission Grant. Google treats scope consent as trust in the project-level application, so project-level revocation may affect both profiles; accepting that coupling avoids duplicating consent branding, publishing configuration, and maintenance for this one-operator local tool.
