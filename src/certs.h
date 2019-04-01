static char *root_cert="-----BEGIN CERTIFICATE-----\n"\
"MIID8jCCAtqgAwIBAgIPAMJbAAAALPIb2IuDGY54MA0GCSqGSIb3DQEBCjAAMIGR\n"\
"MQswCQYDVQQGEwJVSzEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24x\n"\
"FDASBgNVBAoTC0NJIFBsdXMgTExQMQ8wDQYDVQQLEwZFdXJvcGUxEzARBgNVBAsT\n"\
"ClByb2R1Y3Rpb24xJDAiBgNVBAMTG0NJIFBsdXMgUm9vdCBDQSBjZXJ0aWZpY2F0\n"\
"ZTAeFw0wODExMjYxMzE5NDVaFw05OTEyMzEyMzU5NTlaMIGRMQswCQYDVQQGEwJV\n"\
"SzEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xFDASBgNVBAoTC0NJ\n"\
"IFBsdXMgTExQMQ8wDQYDVQQLEwZFdXJvcGUxEzARBgNVBAsTClByb2R1Y3Rpb24x\n"\
"JDAiBgNVBAMTG0NJIFBsdXMgUm9vdCBDQSBjZXJ0aWZpY2F0ZTCCASIwDQYJKoZI\n"\
"hvcNAQEBBQADggEPADCCAQoCggEBAKjQXys5nZPzKshu6CY6sBZI/2+7cC7/7xK8\n"\
"+dMpajT40qJLVzmQcewzVXdKSXyVmnDmb7RY5bgRve/CHtHORVlfjy9RmEK7/haQ\n"\
"YqO/kgbBo5mVEhQobPvO/Hp92NaZ6yQUbWF8TjMBTUtWlzP1pQLNAUmlEd1fxXL9\n"\
"hvJ1FHgbzkQcmuscDFqszJPuAfjriw/Jprt3M7oTGsf8SQliunzaKSOvM/Ns/lCc\n"\
"23gWJ4b5X1EvlqqPs6stYBT5EmmS+3DrXpQCO2dCSyb8qfOlXGZb5mtWhUdiuuV7\n"\
"K0GZqUMihrqlKaKazjFLuvMe0UAu+r69Nkwsl/CFHDUJP5CGHXkCAwEAAaNFMEMw\n"\
"EgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFCfI\n"\
"dc69fUR0sXtrnUmhwnmA2C4/MA0GCSqGSIb3DQEBCjAAA4IBAQARgWJ8ij+ajLND\n"\
"Bn7YAmIGrC866WbXmk3Y7KJAF5Gz4D7s4e/2mKe8iITahH8XyPanyDuJz4Y7urZe\n"\
"OraEiSPXBPoaYD4mcwLXLtFKgsi4RBm6UTdUJvc+kb1UMU5/wcIPL9YBO/rulxO8\n"\
"DylcKoeS+266XSrpQqyM9G0o8LpkPCC1zPHtvMXvMJ0D4nzIzkc0TeaMaV0sEra2\n"\
"ZezfrlwKmjfusTUDwauxnyEtN6gTiPhCLyVAMuj2YJsgiUJfuXCLbAfeVCtu/OSt\n"\
"/jM6Jb8J62T+cdR82mQN4qk8cquOa//9xulgkZQWRhXn5CcGHhEuqRna4XXQBP0G\n"\
"s0F7yul/\n"\
"-----END CERTIFICATE-----\n";

static int root_cert_len;
BIO *root_bio = NULL;

char *customer_cert="-----BEGIN CERTIFICATE-----\n"\
"MIIEFDCCAvygAwIBAgIPAJOQAAAALIwkZ0fLs/1sMA0GCSqGSIb3DQEBCjAAMIGR\n"\
"MQswCQYDVQQGEwJVSzEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24x\n"\
"FDASBgNVBAoTC0NJIFBsdXMgTExQMQ8wDQYDVQQLEwZFdXJvcGUxEzARBgNVBAsT\n"\
"ClByb2R1Y3Rpb24xJDAiBgNVBAMTG0NJIFBsdXMgUm9vdCBDQSBjZXJ0aWZpY2F0\n"\
"ZTAeFw0xMDA0MTMxNTA2NTFaFw05OTEyMzEyMzU5NTlaMIGSMQswCQYDVQQGEwJL\n"\
"UjEOMAwGA1UECBMFU2VvdWwxDjAMBgNVBAcTBVNlb3VsMR4wHAYDVQQKExVHaUJh\n"\
"aG4gTWVkaWEgQ28uLCBMdGQxEzARBgNVBAsTClByb2R1Y3Rpb24xLjAsBgNVBAMT\n"\
"JUNJIFBsdXMgUk9UIGZvciBHaUJhaG4gTWVkaWEgQ28uLCBMdGQwggEiMA0GCSqG\n"\
"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWX5+6O1wX4CEck2vRH7vMzqvph/wx8s7T\n"\
"8yTJ7ApvZqHtV+TxBxR7+omdOVN4UuR4EwExB+EGd1FqPNhuyzz612Ymz8hQskMA\n"\
"KlrVR0bl7Mkp6+NL6BQldNp9/fAEStGurjHnalXCcerMbBFvhcPGzLPGVWBmBqqi\n"\
"Od2Djn/Db+AEME/OoPnILNs5kiF0re7RBba/aMkxkJd+w+f4aIsDQlwll6TbQ8ZN\n"\
"xEiJRPqWv8iGX/QS2M186Czi+eEVuiIwGn+yeNWTF8pChiod57zTfcWTfCesJwNH\n"\
"ZdKtFPoRt14zR9DKyArDSNDxP8F9BHvOfvmRAjS6JFKrrPh75/hJAgMBAAGjZjBk\n"\
"MB8GA1UdIwQYMBaAFCfIdc69fUR0sXtrnUmhwnmA2C4/MBIGA1UdEwEB/wQIMAYB\n"\
"Af8CAQAwDgYDVR0PAQH/BAQDAgIEMB0GA1UdDgQWBBTpgrWLlAPj2JLyPmh4VnBc\n"\
"GJHwbDANBgkqhkiG9w0BAQowAAOCAQEAPeNmhbLRya1sTwCjn8TRMfIGu+i6t9da\n"\
"TGGhi+5MXC5+xV/GS4SfOu8+gcXMMSMPQE2jQZ7ffAOCTgTQs4dhLtKitgn+caVD\n"\
"ZHRYDEEfor8DJOx6GAysGiiGap40/ANjaaOU7CUv9Qlo+8NqQTCi/YHCQtBAm7Ex\n"\
"L46ZvELixHS5CFFu8tCnBNF68ZbaYdOGzYEcklr1DSzRFykw74hTl3ntuGWd/G9x\n"\
"K9BQyjk9dOb2NPjoQWalKtzEQXBPRSiJl23DyndvEq8hQCfGya/IdRu4Z3TlGSEo\n"\
"rk4s5IGjLs3B5/s5tOz9WPFw6Os7moXPDXi9aE520ovcavf/+IdKmw==\n"\
"-----END CERTIFICATE-----\n";

static int customer_cert_len;
BIO *customer_bio = NULL;

static char *device_cert="-----BEGIN CERTIFICATE-----\n"\
"MIIEBjCCAu6gAwIBAgINaQAAACy7Tx7s7MtpUTANBgkqhkiG9w0BAQowADCBkjEL\n"\
"MAkGA1UEBhMCS1IxDjAMBgNVBAgTBVNlb3VsMQ4wDAYDVQQHEwVTZW91bDEeMBwG\n"\
"A1UEChMVR2lCYWhuIE1lZGlhIENvLiwgTHRkMRMwEQYDVQQLEwpQcm9kdWN0aW9u\n"\
"MS4wLAYDVQQDEyVDSSBQbHVzIFJPVCBmb3IgR2lCYWhuIE1lZGlhIENvLiwgTHRk\n"\
"MB4XDTEwMDYxNTEwNTgzMloXDTYwMDYxNTEwNTgzMlowgZExCzAJBgNVBAYTAktS\n"\
"MQ4wDAYDVQQIEwVTZW91bDEOMAwGA1UEBxMFU2VvdWwxHjAcBgNVBAoTFUdpQmFo\n"\
"biBNZWRpYSBDby4sIEx0ZDETMBEGA1UECxMKUHJvZHVjdGlvbjESMBAGA1UECxMJ\n"\
"VFZMSVRFLVM1MRkwFwYDVQQDExA0RTI5N0QzMDBFMDE0REYxMIIBIjANBgkqhkiG\n"\
"9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4UTVhF3YBKFYEbeefvl7JU1ixFBkvblEuHRP\n"\
"epcZq42GiKYlF3zSP1qOPm4SSORh5JHSwB+iZ+4XKoBOc3BSbQiVXW1A/feMIkiH\n"\
"9mnxvax7HOFIOtS6adaEjm+JFCDDUte5UWyTbhZcPRfPGIAw4kodFzbJnTXQHdXm\n"\
"My6qM3xcuo6TKQ9dnbDSAWbB+Gj8M0nIS521caYnQHUK8eqz/1Qa9+BK41kGCNdq\n"\
"igHwsqPG0Yri/ir3ZcFK3ccgXMMOQVwtw92hRim+Lvbco/+xzR9uSvrTF09XsE/d\n"\
"/l+xK3rNlNOuylMKbAadxxM0PSIInqbOzuxrR43DMyErh5mBqQIDAQABo1owWDAf\n"\
"BgNVHSMEGDAWgBTpgrWLlAPj2JLyPmh4VnBcGJHwbDAMBgNVHRMBAf8EAjAAMA4G\n"\
"A1UdDwEB/wQEAwIHgDAXBggrBgEFBQcBGQEB/wQIMAYCAQECAQAwDQYJKoZIhvcN\n"\
"AQEKMAADggEBAERo6j3Gn8bZRfjb3/uHEuUL1YBYhMnjI1WZiTOoIAocvEUb9HsT\n"\
"UU7r4WYw5C9L6Z3+b7sAgD8KIOCO8h4gXDGO6YQSsBPDkbSc5b2C+97PnS5koBRc\n"\
"g03frcC+7B8BlA9eG4RTIrous5a3u+qcpXW7q57iEEUfQckvm2lQJQ2sHAsifVIY\n"\
"NVrFDhEoz1qucoYjjpAb75rVNKYhVJPtfK5SjRi6qOp43qHEgA9oRtHswT5ppaIZ\n"\
"A98cJpH7xurz0kja5kFu/6cI5ztzTZjwXwf7h47z0mIqYRI1uoaSRp3ei3H+JWv6\n"\
"gF6FplRoZg3/xSJNnPGi2CI+w/FDXAk5hwc=\n"\
"-----END CERTIFICATE-----\n"\
"-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEogIBAAKCAQEA4UTVhF3YBKFYEbeefvl7JU1ixFBkvblEuHRPepcZq42GiKYl\n"\
"F3zSP1qOPm4SSORh5JHSwB+iZ+4XKoBOc3BSbQiVXW1A/feMIkiH9mnxvax7HOFI\n"\
"OtS6adaEjm+JFCDDUte5UWyTbhZcPRfPGIAw4kodFzbJnTXQHdXmMy6qM3xcuo6T\n"\
"KQ9dnbDSAWbB+Gj8M0nIS521caYnQHUK8eqz/1Qa9+BK41kGCNdqigHwsqPG0Yri\n"\
"/ir3ZcFK3ccgXMMOQVwtw92hRim+Lvbco/+xzR9uSvrTF09XsE/d/l+xK3rNlNOu\n"\
"ylMKbAadxxM0PSIInqbOzuxrR43DMyErh5mBqQIDAQABAoIBABKNDZxR8hknhE4p\n"\
"Nec0+lwvDEQobrNlD3C1O1pYGSgUhpC4RfOyNso61d30SJMyI5GkJJvnvwMaC1RX\n"\
"rp45EMCj5VEFT0Xa3fJw0KmNPfglvRm6v60Amb1fihkEvGAo9oza8Qrwiw+UzdHG\n"\
"JSraW6w2+EBSJbZJmTLry4JJhICqxJU0jZqafnvkn2cyoR2CuWFhxDqjOmrao00T\n"\
"RJlj3BLBsdgWWxLKBAlHXLiImg+ZuGY6LyfJbH4hTGm+xFusuUqhD5eHIsK67Z1Z\n"\
"JiIaH10mwB7VzTUv7uundLO8KZWLfDi31dWXf4FDmqJ4nQzkkvuRI5DsUcmYDCMJ\n"\
"XCnn/oECgYEA9FY3kWGEiYgJPohOwzdOcCaGz3rqjk81M/fsupFlYsV0olOWma3C\n"\
"NxiJr8vaPzVmGysTrqSmfpWYtu+Oi+TZeYzrOBe+5PcWruCOurT+QJsIZZjIGcgW\n"\
"3fOAQlEYJ5R7pIhxq+aMaOzBvewj0kfPmRB3xNPkIxu2Jt8Z3vwX9vECgYEA7AWb\n"\
"szjDFKvHAra1abX24c4YOpYxOqxgPwx0T/diw3b6hwZGyog259PTENcK33FkkPKR\n"\
"s6nLm/uR/1GJ7IgtpmGCpFfLtnsblN3bkECsp+vVzLZH+N8Id6uG+Fp3bi/fV+c9\n"\
"UZwKUHGypBXJ4p8/X5BD2ykYkL+/nze8AxrX5jkCgYBv8Zhf6TfZ8xOZLMY5Nnuf\n"\
"cmdNY9lW/f84Ihy5lafHywOW44kaO7vBlmJuwozpbMOtKt1HpHQLhuqC1dqPSXhB\n"\
"8khKWMbDDFm+IXADJq1eWClOsuLqvPuNEOTwfUr9x0+moETEJ0qpP9+77hazXudE\n"\
"D4FwEkxxsV6RDKJDwWgRYQKBgD6Hwdd6u1x3ojMa2vdVyUHLy2mCLyq/ToSFtS8W\n"\
"eKkWlYs+Y3T3H6zN1waIIo5OSXmJeoah/pqlzOla3fK3pXiGLwmBZSxEc2s+WBRg\n"\
"vh2DAtLInErYNDMYU5rqxOeBcWelkP5VG/pyFQUZ7LHIxQ55dzDSM3ruAkOZjYs5\n"\
"CmgpAoGAZbnAiCbxv/BzdYVrfWwYcC1VwllB72HikxwENKcYs4Fu+/nTUILOEJMe\n"\
"mOT7HJdvZtk9dEPisAhxZ6GwyqscUNCcEfESpNdeINCPdQ3Yn+Pv7+wfFrFTXq3F\n"\
"Lp/M6ptKKeaWamQYbmUP9XKV/qC7w574a0bo3JzzhEgmp4LQfVM=\n"\
"-----END RSA PRIVATE KEY-----\n";

static int device_cert_len;
BIO *device_bio = NULL;
