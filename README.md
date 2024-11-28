# Windows-Server-AD
## 1. Introduction
This project demonstrates the configuration of a Windows Server 2022 environment, focusing on:
1. **Active Directory Domain Services (AD DS)** for centralized user and resource management.
2. **Server Roles**:
   - Internet Information Services (IIS)
   - Domain Name System (DNS)
   - Dynamic Host Configuration Protocol (DHCP)
3. **User Management**:
   - Creation of two user accounts: `Alice` and `Bob`
   - Implementation of **Role-Based Access Control (RBAC)**.
4. **Security Monitoring** using **Sysmon** for enhanced event tracking and analysis.

## 2. Project Goals

1. **Install and configure Windows Server 2022**  
   Set up the server as a foundation for Active Directory and other essential roles.

2. **Deploy and manage Active Directory**  
   Implement centralized user and resource management through Active Directory Domain Services (AD DS).

3. **Configure essential server roles**:  
   - **IIS (Internet Information Services)**: Host web applications.  
   - **DNS (Domain Name System)**: Provide domain name resolution.  
   - **DHCP (Dynamic Host Configuration Protocol)**: Automate IP address allocation.

4. **Create and manage users (Alice and Bob)**  
   - Assign appropriate permissions for each user.  
   - Demonstrate role-based access control (RBAC) for secure user management.

5. **Monitor system activity with Sysmon**  
   Install and configure Sysmon to enhance event logging and security monitoring.

6. **Ensure a secure, functional environment**  
   - Validate the server setup for domain-level user and resource management.  
   - Emphasize security and functionality in all configurations.

## 3. Environment Setup

### 3.1 Virtualization
To simulate the environment, virtualization tools were used.

- **Tools Used**:  
  - VirtualBox  
  - VMware Workstation  

- **Virtual Machines (VMs) Created**:  
  1. **Domain Controller VM**:  
     - Hosts **Active Directory**, **IIS**, **DNS**, and **DHCP**.  
  2. **Client VM**:  
     - Configured to join the domain for user testing and validation.

## 4. Active Directory Setup

### 4.1 Install Active Directory Domain Services (AD DS)

#### Installation Steps:
1. Open **Server Manager**.  
2. Click **Add Roles and Features**.  
3. Select **Active Directory Domain Services (AD DS)** from the list of roles.  
4. Proceed through the wizard and complete the installation.  
5. After installation, promote the server to a **Domain Controller** using the **Active Directory Domain Services Configuration Wizard**.

![Active Directory Setup Screenshot](images/screenshot.png)

### 4.2 Promote Server to Domain Controller

#### Steps to Promote the Server:

1. **Access Post-Deployment Configuration**:
   - Open **Server Manager**.  
   - Click **Post-Deployment Configuration**.  
   - Select **Promote this server to a domain controller**.

2. **Configuration**:
   - Choose **Add a new forest**.  
   - Enter the **root domain name** (e.g., `mydomain.local`).  

3. **Set Directory Services Restore Mode (DSRM) Password**:
   - Enter and confirm a strong password for **DSRM**.

4. **Complete the Process**:
   - Review and confirm the settings.  
   - Start the configuration and allow the server to reboot after the setup is complete.

### 4.3 DNS Configuration

To configure DNS on the Domain Controller and ensure it uses its own IP address (e.g., `192.168.1.10`) for DNS, follow these steps:

#### Steps to Set Static IP and Configure DNS:

1. **Set a Static IP Address**:
   - Open **Network and Sharing Center**.
   - Click on **Change adapter settings**.
   - Right-click your active network adapter and select **Properties**.
   - In the **Networking** tab, select **Internet Protocol Version 4 (TCP/IPv4)** and click **Properties**.
   - Set a static IP address (e.g., `192.168.1.10`) and configure the subnet mask and default gateway as required.
   - For **Preferred DNS server**, enter the server’s own IP address (e.g., `192.168.1.10`), which will point to the DNS role running on the server.

2. **Verify DNS Role Functionality**:
   - Open **DNS Manager** from the **Server Manager** → **Tools** → **DNS**.
   - Verify that the DNS server is installed and running.
   - In **DNS Manager**, ensure that your domain (e.g., `mydomain.local`) is listed under **Forward Lookup Zones**.
   - Confirm that the necessary DNS records (such as **A records** for the domain controller) are automatically created after promotion.

3. **Test DNS Resolution**:
   - Open **Command Prompt** and run:
     ```bash
     nslookup mydomain.local
     ```
   - The output should return the IP address of your Domain Controller, confirming that the DNS server is working correctly.

4. **Check DNS Service Status**:
   - You can also check the DNS service status in **Server Manager**. Go to **Tools** → **Services**, and ensure that the **DNS Server** service is running.

By ensuring the server uses its own IP address for DNS and verifying DNS functionality, you will have a properly configured DNS server for Active Directory operations.

### 4.4 Organizational Units (OUs)

Organizational Units (OUs) are containers in Active Directory used to organize objects such as users, groups, and computers. In this step, we will create two OUs: **Admins** for administrators like Alice, and **Standard Users** for standard users like Bob.

#### Steps to Create Organizational Units (OUs):

1. **Open Active Directory Users and Computers**:
   - Open **Server Manager**.
   - From **Tools**, select **Active Directory Users and Computers**. This will launch the ADUC console.

2. **Create the Admins OU**:
   - In the left pane of **Active Directory Users and Computers**, right-click on your domain name (e.g., `mydomain.local`).
   - Select **New** → **Organizational Unit**.
   - In the **New Organizational Unit** dialog box:
     - Name the OU as **Admins**.
     - Optionally, check **Protect container from accidental deletion** to prevent accidental deletion of the OU.
   - Click **OK** to create the **Admins** OU.

3. **Create the Standard Users OU**:
   - Again, right-click on your domain name (e.g., `mydomain.local`).
   - Select **New** → **Organizational Unit**.
   - In the **New Organizational Unit** dialog box:
     - Name the OU as **Standard Users**.
     - Optionally, check **Protect container from accidental deletion**.
   - Click **OK** to create the **Standard Users** OU.

4. **Verify OUs Creation**:
   - You should now see the newly created **Admins** and **Standard Users** OUs listed under your domain in **Active Directory Users and Computers**.
   - Expand the domain tree, and you should see both **Admins** and **Standard Users** as child OUs.

By creating these OUs, we can organize users based on their roles, such as placing Alice in the **Admins** OU and Bob in the **Standard Users** OU, which helps in applying group policies and delegating administrative tasks more efficiently.


### 5. User Management

#### 5.1 Create User Accounts

In this step, we will create user accounts for Alice (an Administrator) and Bob (a Standard User) in the respective Organizational Units (OUs) we created earlier.

#### Steps to Create Alice (Administrator):

1. **Navigate to the Admins OU**:
   - In **Active Directory Users and Computers**, expand the domain (e.g., `mydomain.local`).
   - Right-click on the **Admins** OU and select **New** → **User**.

2. **Create the User Account for Alice**:
   - In the **New Object - User** dialog box:
     - Enter **First name**: `Alice`, and **Last name**: `Admin`.
     - **User logon name**: Enter a username for Alice, e.g., `alice`.
     - Click **Next**.

3. **Set Password for Alice**:
   - Set a strong password for Alice.
   - Choose **Password never expires** (optional, but recommended for admin accounts).
   - Select **User must change password at next logon** (optional, depending on your security requirements).
   - Click **Next**.

4. **Assign Group Membership (Domain Admins)**:
   - On the **Group Membership** screen, click **Add** to assign Alice to the **Domain Admins** group.
     - In the **Select Groups** dialog box, type **Domain Admins** and click **Check Names** to verify.
     - Click **OK** to add Alice to the **Domain Admins** group.
   - Click **Next** and then **Finish** to create the user.

#### Steps to Create Bob (Standard User):

1. **Navigate to the Standard Users OU**:
   - In **Active Directory Users and Computers**, right-click on the **Standard Users** OU and select **New** → **User**.

2. **Create the User Account for Bob**:
   - In the **New Object - User** dialog box:
     - Enter **First name**: `Bob`, and **Last name**: `User`.
     - **User logon name**: Enter a username for Bob, e.g., `bob`.
     - Click **Next**.

3. **Set Password for Bob**:
   - Set a password for Bob.
   - Choose **User must change password at next logon** (recommended for standard users).
   - Click **Next**.

4. **Assign Group Membership (Domain Users)**:
   - On the **Group Membership** screen, verify that Bob is a member of the **Domain Users** group (which is the default for new users).
   - Click **Next** and then **Finish** to create the user.

---

#### Verify User Accounts:

1. **Check Alice's Account**:
   - In **Active Directory Users and Computers**, navigate to the **Admins** OU and verify that Alice's account is listed.
   - Right-click Alice's account and select **Properties** to check if she is a member of the **Domain Admins** group.

2. **Check Bob's Account**:
   - In **Active Directory Users and Computers**, navigate to the **Standard Users** OU and verify that Bob's account is listed.
   - Right-click Bob's account and select **Properties** to check if he is a member of the **Domain Users** group.

By completing these steps, we will have created the user accounts for Alice and Bob and assigned them the appropriate group memberships based on their roles.

### 5.2 Group Policy Objects (GPOs)

In this step, we will create and configure Group Policy Objects (GPOs) to define specific settings for Alice (Administrator) and Bob (Standard User) based on their roles.

#### Steps to Create and Link GPOs:

1. **Open Group Policy Management**:
   - In **Server Manager**, click on **Tools** and select **Group Policy Management**.
   - This will open the **Group Policy Management Console (GPMC)**.

2. **Create GPO for Alice (Administrator)**:
   - In **Group Policy Management**, navigate to your domain (e.g., `mydomain.local`).
   - Right-click on **Group Policy Objects** in the left pane and select **New**.
   - Name the GPO something like **Alice_Admin_Policies** and click **OK**.

3. **Configure Alice's GPO**:
   - Right-click on the newly created GPO (**Alice_Admin_Policies**) and select **Edit** to open the **Group Policy Management Editor**.
   - Under **User Configuration** → **Policies** → **Administrative Templates**, configure the following settings:
     - **Allow admin rights**: Make sure Alice has access to administrative tools.
       - Navigate to **Start Menu and Taskbar** → **Do not use the search-based method when resolving shell shortcuts** and configure it according to your needs.
     - **Configure Desktop Policies**:
       - Under **Desktop** → **Active Desktop**, configure settings as needed to allow a customizable desktop experience for Alice.

4. **Link GPO for Alice**:
   - In **Group Policy Management**, right-click on the **Admins** OU (where Alice's account is located) and select **Link an Existing GPO**.
   - Select the **Alice_Admin_Policies** GPO from the list and click **OK** to link it to the **Admins** OU.

5. **Create GPO for Bob (Standard User)**:
   - In **Group Policy Management**, right-click on **Group Policy Objects** in the left pane and select **New**.
   - Name the GPO something like **Bob_Standard_User_Policies** and click **OK**.

6. **Configure Bob's GPO**:
   - Right-click on the newly created GPO (**Bob_Standard_User_Policies**) and select **Edit** to open the **Group Policy Management Editor**.
   - Under **User Configuration** → **Policies** → **Administrative Templates**, configure the following settings:
     - **Restrict access to Control Panel**:
       - Navigate to **Control Panel** → **Prohibit access to Control Panel and PC settings**, and set this to **Enabled** to restrict access to the Control Panel.
     - **Disable Run Command**:
       - Navigate to **Start Menu and Taskbar** → **Remove Run menu from Start Menu**, and set this to **Enabled** to disable the Run command for Bob.

7. **Link GPO for Bob**:
   - In **Group Policy Management**, right-click on the **Standard Users** OU (where Bob's account is located) and select **Link an Existing GPO**.
   - Select the **Bob_Standard_User_Policies** GPO from the list and click **OK** to link it to the **Standard Users** OU.

---

#### Verify GPOs:

1. **Verify Alice's GPO**:
   - Log in as **Alice** and check if she has administrative rights and the desktop settings configured by the GPO.
   - Verify that she can access the necessary administrative tools.

2. **Verify Bob's GPO**:
   - Log in as **Bob** and check if the access to **Control Panel** is restricted and the **Run Command** is disabled, as specified in the GPO.

By following these steps, we will have successfully created and linked GPOs to manage the desktop and security settings for Alice and Bob based on their roles.

### 6. Server Roles Configuration

#### 6.1 IIS Configuration

In this step, we will install and configure **Internet Information Services (IIS)** on the server, then test the IIS functionality by hosting a simple HTML file.

#### Steps to Install IIS:

1. **Open Server Manager**:
   - In **Server Manager**, click on **Manage** in the top right corner and select **Add Roles and Features**.

2. **Select IIS Role**:
   - In the **Add Roles and Features Wizard**, click **Next** until you reach the **Select Features** page.
   - On the **Select Features** page, you can leave the default selections, then click **Next**.

3. **Install IIS**:
   - On the **Select Roles** page, check the box for **Web Server (IIS)**.
   - Click **Next** to proceed.
   - Review your selections and click **Install** to begin the installation of IIS.
   - Once the installation is complete, click **Close**.

#### Steps to Test IIS:

1. **Place a Test HTML File in IIS Directory**:
   - Navigate to the **C:\inetpub\wwwroot** directory on your server.
   - Create a simple HTML file, such as `index.html`, with the following content:
     ```html
     <html>
       <head><title>Test Page</title></head>
       <body>
         <h1>Welcome to IIS!</h1>
         <p>This is a test page hosted on IIS.</p>
       </body>
     </html>
     ```
   - Save the file in **C:\inetpub\wwwroot**.

2. **Test IIS in a Web Browser**:
   - Open a web browser on the server or a client machine within the same network.
   - In the browser's address bar, type the server's IP address (e.g., `http://192.168.1.10`) to access the test HTML file hosted by IIS.

3. **Verify IIS Functionality**:
   - If IIS is properly configured, you should see the **Welcome to IIS!** message displayed on the test page, confirming that the IIS web server is working as expected.

By following these steps, we will have successfully installed IIS, configured it to serve a test HTML page, and verified its functionality.

### 6.2 DHCP Configuration

In this step, we will install and configure the **DHCP Server** role on the server to automatically assign IP addresses to devices on the network.

#### Steps to Install DHCP Server:

1. **Open Server Manager**:
   - In **Server Manager**, click on **Manage** in the top right corner and select **Add Roles and Features**.

2. **Select DHCP Server Role**:
   - In the **Add Roles and Features Wizard**, click **Next** until you reach the **Select Roles** page.
   - On the **Select Roles** page, check the box for **DHCP Server**.
   - Click **Next** to proceed through the wizard.

3. **Install DHCP Server**:
   - Review your selections and click **Install** to begin the installation of the DHCP Server role.
   - Once the installation is complete, click **Close** to finish.

#### Steps to Configure DHCP:

1. **Open DHCP Management Console**:
   - In **Server Manager**, click on **Tools** in the top right corner and select **DHCP** to open the **DHCP Management Console**.

2. **Create a New DHCP Scope**:
   - In the **DHCP Management Console**, expand the server node (e.g., `DHCP Server`) and right-click on **IPv4**.
   - Select **New Scope** from the context menu to open the **New Scope Wizard**.
   
3. **Configure Scope Settings**:
   - **Name the Scope**: Enter a name for the new scope (e.g., **Office DHCP Scope**) and click **Next**.
   - **IP Address Range**:
     - Enter the **Start IP Address** (e.g., `192.168.1.100`) and the **End IP Address** (e.g., `192.168.1.200`).
     - Enter the **Subnet Mask** (e.g., `255.255.255.0`).
     - Click **Next**.
   - **Exclusions**: If needed, you can exclude specific IP addresses from being assigned (e.g., static IPs for servers or printers). If there are no exclusions, click **Next**.
   - **Lease Duration**: You can configure the lease duration, which determines how long a client will hold an IP address. Use the default or adjust as needed, and click **Next**.

4. **Configure DHCP Options**:
   - The wizard will prompt you to configure DHCP options. This includes setting the **Router (Default Gateway)** and **DNS Servers**.
   - Enter the appropriate **Default Gateway** (e.g., `192.168.1.1`) and **DNS Server** (e.g., `192.168.1.10`).
   - Click **Next** and proceed with the default options until you reach the end of the wizard.

5. **Activate the Scope**:
   - On the final screen of the wizard, choose to **Activate this scope now** and click **Finish**.
   - The new scope will now appear under **IPv4** in the **DHCP Management Console**, and it will be activated to start assigning IP addresses to clients.

#### Verify DHCP Functionality:

1. **Check DHCP Scope**:
   - In the **DHCP Management Console**, under **IPv4**, verify that your new scope (e.g., **Office DHCP Scope**) appears with a status of **Active**.

2. **Test DHCP on a Client Machine**:
   - On a client machine, set the network adapter to obtain an IP address automatically (via DHCP).
   - Once the client machine is connected to the network, open **Command Prompt** and type `ipconfig /renew` to request a new IP address.
   - Verify that the client receives an IP address within the range specified (e.g., `192.168.1.100-192.168.1.200`).

By following these steps, we will have successfully installed and configured the DHCP Server role and created a DHCP scope that automatically assigns IP addresses to devices on your network.

### 7. Monitoring with Sysmon

#### 7.1 Sysmon Installation

**Sysmon (System Monitor)** is a powerful tool from the Sysinternals suite used for monitoring system activity and enhancing security logging.

---

#### Steps to Install and Configure Sysmon:

1. **Download Sysmon**:
   - Visit the [Sysinternals website](https://learn.microsoft.com/en-us/sysinternals/) and download **Sysmon**.

2. **Prepare Configuration File**:
   - Create or download a Sysmon configuration file (`config.xml`) tailored to your logging needs.
     - For a detailed example, you can use the [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config), a popular prebuilt configuration that captures a broad range of events.

3. **Install Sysmon**:
   - Open a **Command Prompt** or **PowerShell** with administrative privileges.
   - Run the following command to install Sysmon and specify your configuration file:
     ```cmd
     Sysmon64.exe -accepteula -i config.xml
     ```
     - `-accepteula`: Automatically accepts the license agreement.
     - `-i config.xml`: Installs Sysmon with the specified configuration.

4. **Verify Installation**:
   - After installation, Sysmon runs as a service in the background.
   - Confirm that the Sysmon service is active by typing:
     ```cmd
     sc query sysmon64
     ```

---

#### Configure Logging to Capture Events:

Ensure the Sysmon configuration file includes the following event types for monitoring:

1. **Process Creations**:
   - Logs every time a process is created.
   - Example:
     ```xml
     <EventFiltering>
       <ProcessCreate onmatch="include">
         <Rule groupRelation="or">
           <Image condition="contains">cmd.exe</Image>
           <Image condition="contains">powershell.exe</Image>
         </Rule>
       </ProcessCreate>
     </EventFiltering>
     ```

2. **File Creation Events**:
   - Tracks when files are created or modified.
   - Example:
     ```xml
     <FileCreate onmatch="include">
       <TargetFilename condition="ends with">.exe</TargetFilename>
     </FileCreate>
     ```

3. **Network Connections**:
   - Captures outgoing and incoming network connections.
   - Example:
     ```xml
     <NetworkConnect onmatch="include" />
     ```

---

#### Post-Installation Check:

1. **View Sysmon Logs**:
   - Open **Event Viewer**.
   - Navigate to: 
     **Applications and Services Logs** → **Microsoft** → **Sysmon**.
   - Ensure events for process creations, file creations, and network connections are being logged.

2. **Test Functionality**:
   - Perform actions like running `cmd.exe`, creating test files, or initiating network connections to generate logs.
   - Confirm these events are recorded in the Sysmon log.

With Sysmon installed and configured, we now have an advanced logging mechanism to monitor and analyze system activity in detail.

### 7.2 Analyze Sysmon Logs

In this step, we will analyze **Sysmon** logs to monitor and investigate user activities for Alice and Bob.

#### Steps to Analyze Sysmon Logs:

1. **Open Event Viewer**:
   - Press **Win + R**, type `eventvwr.msc`, and hit **Enter** to open the **Event Viewer**.

2. **Navigate to Sysmon Logs**:
   - In the **Event Viewer** window, expand **Applications and Services Logs** in the left pane.
   - Navigate to **Microsoft** → **Sysmon**.

3. **Filter Sysmon Logs**:
   - Right-click on **Sysmon** and select **Filter Current Log...**.
   - In the filter window, you can filter the logs based on various criteria, such as:
     - **Event IDs**: Specific events related to system activity, process creation, network connections, etc.
     - **Keywords**: For example, search for specific user activities by filtering for the username of Alice or Bob (e.g., `alice` or `bob`).
     - **Time Period**: Filter logs by date and time range if needed.
   - Click **OK** to apply the filter.

4. **Analyze User Activities**:
   - Look for relevant **Sysmon event IDs** to monitor user activities:
     - **Event ID 1**: Process creation (e.g., monitor which applications Alice and Bob run).
     - **Event ID 3**: Network connection activity (e.g., monitor network connections initiated by Alice or Bob).
     - **Event ID 5**: Process terminated (e.g., identify any unexpected processes terminating).
   - Right-click on any relevant event to view **Event Details** and examine the data for specific information about the activity performed by Alice or Bob.

5. **Investigate Suspicious Activities**:
   - Pay close attention to any unusual process execution or network activity that may indicate suspicious behavior.
   - If any unknown or unauthorized processes are identified, investigate further to determine if they are legitimate.

6. **Export Sysmon Logs (Optional)**:
   - You can also export the Sysmon logs for further analysis by selecting **Save All Events As** in the right pane.
   - Choose a location to save the logs in a readable format (e.g., `.evtx`).

By following these steps, we will be able to filter and analyze Sysmon logs to track the activities of Alice and Bob and identify any potential security events or anomalies in your environment.

### 8. Testing and Validation

#### 8.1 Join Client VM to Domain

To test the functionality of the Active Directory environment, we will join a Client VM to the domain and validate login using Alice’s and Bob’s credentials.

---

#### Steps to Join the Client VM to the Domain:

1. **Access System Properties on the Client VM**:
   - Right-click on **This PC** (or **My Computer**) and select **Properties**.
   - In the **System** window, click **Change settings** under the **Computer name, domain, and workgroup settings** section.

2. **Change Computer Settings**:
   - In the **System Properties** dialog, click the **Change...** button.

3. **Join the Domain**:
   - In the **Computer Name/Domain Changes** window:
     - Select **Domain** and enter the domain name (e.g., `mydomain.local`).
     - Click **OK**.

4. **Provide Domain Credentials**:
   - When prompted, enter the credentials of a user with permission to join devices to the domain (e.g., **Alice’s** credentials if she is a Domain Admin).
   - Click **OK**.

5. **Restart the Client VM**:
   - After successfully joining the domain, you will see a confirmation message.
   - Restart the Client VM to apply the changes.

---

#### Steps to Log In Using Alice’s and Bob’s Credentials:

1. **Log in with Alice’s Credentials**:
   - On the Client VM, at the login screen, select **Other User**.
   - Enter Alice’s credentials in the format:
     - **Username**: `mydomain\alice` (or just `alice` if default domain is set).
     - **Password**: Enter Alice’s password.
   - Verify that Alice can log in and access administrative features if configured.

2. **Log in with Bob’s Credentials**:
   - Log out and select **Other User** again.
   - Enter Bob’s credentials in the format:
     - **Username**: `mydomain\bob`.
     - **Password**: Enter Bob’s password.
   - Verify that Bob can log in and that restrictions (e.g., disabled Control Panel and Run command) are applied if GPOs were configured.

---

#### Validation:

- **Check Domain Membership**:
  - On the Client VM, open a Command Prompt and type:
    ```cmd
    systeminfo | findstr /B /C:"Domain"
    ```
    - Verify that the output shows the correct domain (e.g., `mydomain.local`).

- **Verify Policy Application**:
  - Use the `gpresult /r` command on the Client VM to check that the correct Group Policy Objects (GPOs) are applied for Alice and Bob.

By completing these steps, we will confirm that the Client VM has successfully joined the domain and that users Alice and Bob can log in with the expected permissions and restrictions.

### 8.2 Validate GPO Application

To ensure that Group Policy Objects (GPOs) are correctly applied, we will use the `gpresult` command and test access for Alice and Bob to confirm their permissions and restrictions.

---

#### Steps to Validate GPO Application:

1. **Run `gpresult /r` on the Client VM**:
   - Log in to the Client VM using either Alice’s or Bob’s credentials.
   - Open a **Command Prompt** with standard user permissions:
     - Press **Win + R**, type `cmd`, and press **Enter**.
   - Run the following command to generate a summary of applied policies:
     ```cmd
     gpresult /r
     ```
   - Review the output for the following:
     - **User Settings**: Verify that the correct GPOs (e.g., `Alice_Admin_Policies` or `Bob_Standard_User_Policies`) are listed under **Applied Group Policy Objects**.
     - **Computer Settings**: Confirm that domain policies are applied correctly.

2. **Run `gpresult /h` for Detailed Report** (Optional):
   - Generate an HTML report for easier review:
     ```cmd
     gpresult /h C:\GPOReport.html
     ```
   - Open the file `C:\GPOReport.html` in a browser to view a detailed report of all applied policies.

---

#### Test Access for Alice and Bob:

1. **Test Alice’s Access**:
   - Log in as Alice on the Client VM.
   - Verify that Alice has:
     - **Admin-level permissions**: Check that she can access **Administrative Tools**, open **Computer Management**, and make system changes.
     - **Unrestricted desktop policies**: Confirm that Alice's desktop environment is fully functional and matches configured GPO settings.

2. **Test Bob’s Access**:
   - Log in as Bob on the Client VM.
   - Verify that Bob has:
     - **Restricted access to Control Panel**: Attempt to open the Control Panel. It should be blocked if the GPO is correctly applied.
     - **Disabled Run Command**: Press **Win + R**. The Run dialog should be disabled, preventing access to commands.

---

#### Validation:

- **Successful Validation for Alice**:
  - Alice’s GPOs allow administrative tasks and a customizable desktop environment.

- **Successful Validation for Bob**:
  - Bob’s GPOs restrict access as configured (e.g., Control Panel blocked, Run Command disabled).

By following these steps, we will confirm that the GPOs are properly applied and functioning as intended for Alice and Bob based on their respective roles.


### Conclusion

This project successfully set up a fully functional **Windows Server 2022 Active Directory environment**, featuring:

- **Active Directory Domain Services (AD DS)** for centralized user and resource management.
- **DNS and DHCP roles** to provide network services essential for domain operations.
- **Role-based user management**, ensuring secure and appropriate permissions for users like Alice and Bob.
- **Sysmon installation and log analysis** for advanced security monitoring.
  
The configuration achieves the following objectives:
- Demonstrates the implementation of critical server roles (DNS, DHCP, IIS).
- Validates secure domain-level user access and role-based control.
- Showcases the use of monitoring tools to enhance the security and auditing of the environment.

This setup ensures a scalable and secure domain environment that can serve as a foundation for further enterprise-level deployments or testing scenarios.
