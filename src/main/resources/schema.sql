INSERT INTO `users` (`username`, `password`, `authority`)
VALUES (`bill`, `12345`, `read`);

INSERT INTO `clients` (`client_id`, `secret`, `scope`, `auth_method`, `grant_type`, `redirect_uri`)
VALUES (`client`, `secret`, `openid`, `client_secret_basic`, `authorization_code`,
        `https://www.vmware.com/explore/us/authorized`);