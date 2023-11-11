# Create a new ADSI linked server, where '@datasrc=' contains the name of the domain controller

EXEC master.dbo.sp_addlinkedserver
	@server = N'linkADSI',
	@srvproduct=N'Active Directory Service Interfaces',
	@provider=N'ADSDSOObject',
	@datasrc=N'DC01.DOMAIN.LOCAL';

# Configure authentication to the ADSI linked server.

EXEC master.dbo.sp_addlinkedsrvlogin
	@rmtsrvname=N'linkADSI',
	@useself=N'False',
	@locallogin=NULL,
	@rmtuser=N'DOMAIN\user',
	@rmtpassword='password';


# Test to see if the link has been created.

SELECT * FROM OPENQUERY( linkADSI, 'SELECT * from ''LDAP://domain.local'' where name=''Administrator'' ')
