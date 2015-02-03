
SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;



SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;


CREATE TABLE api2_token (
    key character varying(40) NOT NULL,
    "user" character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL
);




CREATE TABLE api2_tokenv2 (
    key character varying(40) NOT NULL,
    "user" character varying(255) NOT NULL,
    platform character varying(32) NOT NULL,
    device_id character varying(40) NOT NULL,
    device_name character varying(40) NOT NULL,
    platform_version character varying(16) NOT NULL,
    client_version character varying(16) NOT NULL,
    last_accessed timestamp with time zone NOT NULL,
    last_login_ip character(39) DEFAULT NULL::bpchar
);




CREATE TABLE avatar_avatar (
    id integer NOT NULL,
    emailuser character varying(255) NOT NULL,
    "primary" boolean NOT NULL,
    avatar character varying(1024) NOT NULL,
    date_uploaded timestamp with time zone NOT NULL
);




CREATE SEQUENCE avatar_avatar_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE avatar_avatar_id_seq OWNED BY avatar_avatar.id;



CREATE TABLE avatar_groupavatar (
    id integer NOT NULL,
    group_id character varying(255) NOT NULL,
    avatar character varying(1024) NOT NULL,
    date_uploaded timestamp with time zone NOT NULL
);




CREATE SEQUENCE avatar_groupavatar_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE avatar_groupavatar_id_seq OWNED BY avatar_groupavatar.id;



CREATE TABLE base_commandslastcheck (
    id integer NOT NULL,
    command_type character varying(100) NOT NULL,
    last_check timestamp with time zone NOT NULL
);




CREATE SEQUENCE base_commandslastcheck_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_commandslastcheck_id_seq OWNED BY base_commandslastcheck.id;



CREATE TABLE base_dirfileslastmodifiedinfo (
    id integer NOT NULL,
    repo_id character varying(36) NOT NULL,
    parent_dir text NOT NULL,
    parent_dir_hash character varying(12) NOT NULL,
    dir_id character varying(40) NOT NULL,
    last_modified_info text NOT NULL
);




CREATE SEQUENCE base_dirfileslastmodifiedinfo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_dirfileslastmodifiedinfo_id_seq OWNED BY base_dirfileslastmodifiedinfo.id;



CREATE TABLE base_filecontributors (
    id integer NOT NULL,
    repo_id character varying(36) NOT NULL,
    file_id character varying(40) NOT NULL,
    file_path text NOT NULL,
    file_path_hash character varying(12) NOT NULL,
    last_modified bigint NOT NULL,
    last_commit_id character varying(40) NOT NULL,
    emails text NOT NULL
);




CREATE SEQUENCE base_filecontributors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_filecontributors_id_seq OWNED BY base_filecontributors.id;



CREATE TABLE base_filediscuss (
    id integer NOT NULL,
    group_message_id integer NOT NULL,
    repo_id character varying(36) NOT NULL,
    path text NOT NULL,
    path_hash character varying(12) NOT NULL
);




CREATE SEQUENCE base_filediscuss_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_filediscuss_id_seq OWNED BY base_filediscuss.id;



CREATE TABLE base_filelastmodifiedinfo (
    id integer NOT NULL,
    repo_id character varying(36) NOT NULL,
    file_id character varying(40) NOT NULL,
    file_path text NOT NULL,
    file_path_hash character varying(12) NOT NULL,
    last_modified bigint NOT NULL,
    email character varying(75) NOT NULL
);




CREATE SEQUENCE base_filelastmodifiedinfo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_filelastmodifiedinfo_id_seq OWNED BY base_filelastmodifiedinfo.id;



CREATE TABLE base_groupenabledmodule (
    id integer NOT NULL,
    group_id character varying(10) NOT NULL,
    module_name character varying(20) NOT NULL
);




CREATE SEQUENCE base_groupenabledmodule_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_groupenabledmodule_id_seq OWNED BY base_groupenabledmodule.id;



CREATE TABLE base_innerpubmsg (
    id integer NOT NULL,
    from_email character varying(75) NOT NULL,
    message character varying(500) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL
);




CREATE SEQUENCE base_innerpubmsg_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_innerpubmsg_id_seq OWNED BY base_innerpubmsg.id;



CREATE TABLE base_innerpubmsgreply (
    id integer NOT NULL,
    reply_to_id integer NOT NULL,
    from_email character varying(75) NOT NULL,
    message character varying(150) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL
);




CREATE SEQUENCE base_innerpubmsgreply_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_innerpubmsgreply_id_seq OWNED BY base_innerpubmsgreply.id;



CREATE TABLE base_userenabledmodule (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    module_name character varying(20) NOT NULL
);




CREATE SEQUENCE base_userenabledmodule_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_userenabledmodule_id_seq OWNED BY base_userenabledmodule.id;



CREATE TABLE base_userlastlogin (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    last_login timestamp with time zone NOT NULL
);




CREATE SEQUENCE base_userlastlogin_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_userlastlogin_id_seq OWNED BY base_userlastlogin.id;



CREATE TABLE base_userstarredfiles (
    id integer NOT NULL,
    email character varying(75) NOT NULL,
    org_id integer NOT NULL,
    repo_id character varying(36) NOT NULL,
    path text NOT NULL,
    is_dir boolean NOT NULL
);




CREATE SEQUENCE base_userstarredfiles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_userstarredfiles_id_seq OWNED BY base_userstarredfiles.id;



CREATE TABLE base_uuidobjidmap (
    id integer NOT NULL,
    uuid character varying(40) NOT NULL,
    obj_id character varying(40) NOT NULL
);




CREATE SEQUENCE base_uuidobjidmap_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_uuidobjidmap_id_seq OWNED BY base_uuidobjidmap.id;



CREATE TABLE captcha_captchastore (
    id integer NOT NULL,
    challenge character varying(32) NOT NULL,
    response character varying(32) NOT NULL,
    hashkey character varying(40) NOT NULL,
    expiration timestamp with time zone NOT NULL
);




CREATE SEQUENCE captcha_captchastore_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE captcha_captchastore_id_seq OWNED BY captcha_captchastore.id;



CREATE TABLE contacts_contact (
    id integer NOT NULL,
    user_email character varying(255) NOT NULL,
    contact_email character varying(255) NOT NULL,
    contact_name character varying(255),
    note character varying(255)
);




CREATE SEQUENCE contacts_contact_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE contacts_contact_id_seq OWNED BY contacts_contact.id;



CREATE TABLE django_content_type (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    app_label character varying(100) NOT NULL,
    model character varying(100) NOT NULL
);




CREATE SEQUENCE django_content_type_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE django_content_type_id_seq OWNED BY django_content_type.id;



CREATE TABLE django_session (
    session_key character varying(40) NOT NULL,
    session_data text NOT NULL,
    expire_date timestamp with time zone NOT NULL
);




CREATE TABLE group_groupmessage (
    id integer NOT NULL,
    group_id integer NOT NULL,
    from_email character varying(255) NOT NULL,
    message character varying(2048) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL
);




CREATE SEQUENCE group_groupmessage_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE group_groupmessage_id_seq OWNED BY group_groupmessage.id;



CREATE TABLE group_messageattachment (
    id integer NOT NULL,
    group_message_id integer NOT NULL,
    repo_id character varying(40) NOT NULL,
    attach_type character varying(5) NOT NULL,
    path text NOT NULL,
    src character varying(20) NOT NULL
);




CREATE SEQUENCE group_messageattachment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE group_messageattachment_id_seq OWNED BY group_messageattachment.id;



CREATE TABLE group_messagereply (
    id integer NOT NULL,
    reply_to_id integer NOT NULL,
    from_email character varying(255) NOT NULL,
    message character varying(2048) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL
);




CREATE SEQUENCE group_messagereply_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE group_messagereply_id_seq OWNED BY group_messagereply.id;



CREATE TABLE group_publicgroup (
    id integer NOT NULL,
    group_id integer NOT NULL
);




CREATE SEQUENCE group_publicgroup_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE group_publicgroup_id_seq OWNED BY group_publicgroup.id;



CREATE TABLE message_usermessage (
    message_id integer NOT NULL,
    message character varying(512) NOT NULL,
    from_email character varying(255) NOT NULL,
    to_email character varying(255) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    ifread boolean NOT NULL,
    sender_deleted_at timestamp without time zone,
    recipient_deleted_at timestamp without time zone
);




CREATE SEQUENCE message_usermessage_message_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE message_usermessage_message_id_seq OWNED BY message_usermessage.message_id;



CREATE TABLE message_usermsgattachment (
    id integer NOT NULL,
    user_msg_id integer NOT NULL,
    priv_file_dir_share_id integer
);




CREATE SEQUENCE message_usermsgattachment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE message_usermsgattachment_id_seq OWNED BY message_usermsgattachment.id;



CREATE TABLE message_usermsglastcheck (
    id integer NOT NULL,
    check_time timestamp with time zone NOT NULL
);




CREATE SEQUENCE message_usermsglastcheck_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE message_usermsglastcheck_id_seq OWNED BY message_usermsglastcheck.id;



CREATE TABLE base_devicetoken (
    id integer NOT NULL,
    token character varying(80) NOT NULL,
    "user" character varying(255) NOT NULL,
    platform character varying(32) NOT NULL,
    version character varying(16) NOT NULL,
    pversion character varying(16) NOT NULL
);




CREATE SEQUENCE base_devicetoken_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE base_devicetoken_id_seq OWNED BY base_devicetoken.id;



CREATE TABLE notifications_notification (
    id integer NOT NULL,
    message character varying(512) NOT NULL,
    "primary" boolean NOT NULL
);




CREATE SEQUENCE notifications_notification_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE notifications_notification_id_seq OWNED BY notifications_notification.id;



CREATE TABLE notifications_usernotification (
    id integer NOT NULL,
    to_user character varying(255) NOT NULL,
    msg_type character varying(30) NOT NULL,
    detail text NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    seen boolean NOT NULL
);




CREATE SEQUENCE notifications_usernotification_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE notifications_usernotification_id_seq OWNED BY notifications_usernotification.id;



CREATE TABLE options_useroptions (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    option_key character varying(50) NOT NULL,
    option_val character varying(50) NOT NULL
);




CREATE SEQUENCE options_useroptions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE options_useroptions_id_seq OWNED BY options_useroptions.id;



CREATE TABLE profile_detailedprofile (
    id integer NOT NULL,
    "user" character varying(255) NOT NULL,
    department character varying(512) NOT NULL,
    telephone character varying(100) NOT NULL
);




CREATE SEQUENCE profile_detailedprofile_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE profile_detailedprofile_id_seq OWNED BY profile_detailedprofile.id;



CREATE TABLE profile_profile (
    id integer NOT NULL,
    "user" character varying(75) NOT NULL,
    nickname character varying(64) NOT NULL,
    intro text NOT NULL,
    lang_code text
);




CREATE SEQUENCE profile_profile_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE profile_profile_id_seq OWNED BY profile_profile.id;

CREATE TABLE pubfile_grouppublicfile (
    id integer NOT NULL,
    group_id integer NOT NULL,
    repo_id character varying(36) NOT NULL,
    path character varying(4096) NOT NULL,
    is_dir boolean NOT NULL,
    added_by character varying(256) NOT NULL,
    description character varying(1024) NOT NULL,
    download_count integer NOT NULL
);


CREATE SEQUENCE pubfile_grouppublicfile_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE pubfile_grouppublicfile_id_seq OWNED BY pubfile_grouppublicfile.id;



CREATE TABLE registration_registrationprofile (
    id integer NOT NULL,
    emailuser_id integer NOT NULL,
    activation_key character varying(40) NOT NULL
);




CREATE SEQUENCE registration_registrationprofile_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE registration_registrationprofile_id_seq OWNED BY registration_registrationprofile.id;



CREATE TABLE share_anonymousshare (
    id integer NOT NULL,
    repo_owner character varying(255) NOT NULL,
    repo_id character varying(36) NOT NULL,
    anonymous_email character varying(255) NOT NULL,
    token character varying(25) NOT NULL
);




CREATE SEQUENCE share_anonymousshare_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE share_anonymousshare_id_seq OWNED BY share_anonymousshare.id;



CREATE TABLE share_fileshare (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    repo_id character varying(36) NOT NULL,
    path text NOT NULL,
    token character varying(10) NOT NULL,
    ctime timestamp with time zone NOT NULL,
    view_cnt integer NOT NULL,
    s_type character varying(2) NOT NULL,
    password text,
    expire_date timestamp without time zone
);




CREATE SEQUENCE share_fileshare_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE share_fileshare_id_seq OWNED BY share_fileshare.id;



CREATE TABLE share_orgfileshare (
    id integer NOT NULL,
    org_id integer NOT NULL,
    file_share_id integer NOT NULL
);




CREATE TABLE share_privatefiledirshare (
    id integer NOT NULL,
    from_user character varying(255) NOT NULL,
    to_user character varying(255) NOT NULL,
    repo_id character varying(36) NOT NULL,
    path text NOT NULL,
    token character varying(10) NOT NULL,
    permission character varying(5) NOT NULL,
    s_type character varying(5) NOT NULL
);




CREATE SEQUENCE share_privatefiledirshare_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE share_privatefiledirshare_id_seq OWNED BY share_privatefiledirshare.id;



CREATE TABLE share_uploadlinkshare (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    repo_id character varying(36) NOT NULL,
    path text NOT NULL,
    token character varying(10) NOT NULL,
    ctime timestamp with time zone NOT NULL,
    view_cnt integer NOT NULL,
    password text,
    expire_date timestamp without time zone
);




CREATE SEQUENCE share_uploadlinkshare_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE share_uploadlinkshare_id_seq OWNED BY share_uploadlinkshare.id;


CREATE TABLE sysadmin_extra_userloginlog (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    login_date timestamp with time zone NOT NULL,
    login_ip character varying(20) NOT NULL
);




CREATE SEQUENCE sysadmin_extra_userloginlog_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE sysadmin_extra_userloginlog_id_seq OWNED BY sysadmin_extra_userloginlog.id;


CREATE TABLE wiki_groupwiki (
    id integer NOT NULL,
    group_id integer NOT NULL,
    repo_id character varying(36) NOT NULL
);




CREATE SEQUENCE wiki_groupwiki_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE wiki_groupwiki_id_seq OWNED BY wiki_groupwiki.id;



CREATE TABLE wiki_personalwiki (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    repo_id character varying(36) NOT NULL
);




CREATE SEQUENCE wiki_personalwiki_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;




ALTER SEQUENCE wiki_personalwiki_id_seq OWNED BY wiki_personalwiki.id;



ALTER TABLE ONLY avatar_avatar ALTER COLUMN id SET DEFAULT nextval('avatar_avatar_id_seq'::regclass);



ALTER TABLE ONLY avatar_groupavatar ALTER COLUMN id SET DEFAULT nextval('avatar_groupavatar_id_seq'::regclass);



ALTER TABLE ONLY base_commandslastcheck ALTER COLUMN id SET DEFAULT nextval('base_commandslastcheck_id_seq'::regclass);



ALTER TABLE ONLY base_dirfileslastmodifiedinfo ALTER COLUMN id SET DEFAULT nextval('base_dirfileslastmodifiedinfo_id_seq'::regclass);



ALTER TABLE ONLY base_filecontributors ALTER COLUMN id SET DEFAULT nextval('base_filecontributors_id_seq'::regclass);



ALTER TABLE ONLY base_filediscuss ALTER COLUMN id SET DEFAULT nextval('base_filediscuss_id_seq'::regclass);



ALTER TABLE ONLY base_filelastmodifiedinfo ALTER COLUMN id SET DEFAULT nextval('base_filelastmodifiedinfo_id_seq'::regclass);



ALTER TABLE ONLY base_groupenabledmodule ALTER COLUMN id SET DEFAULT nextval('base_groupenabledmodule_id_seq'::regclass);



ALTER TABLE ONLY base_innerpubmsg ALTER COLUMN id SET DEFAULT nextval('base_innerpubmsg_id_seq'::regclass);



ALTER TABLE ONLY base_innerpubmsgreply ALTER COLUMN id SET DEFAULT nextval('base_innerpubmsgreply_id_seq'::regclass);



ALTER TABLE ONLY base_userenabledmodule ALTER COLUMN id SET DEFAULT nextval('base_userenabledmodule_id_seq'::regclass);


ALTER TABLE ONLY pubfile_grouppublicfile ALTER COLUMN id SET DEFAULT nextval('pubfile_grouppublicfile_id_seq'::regclass);



ALTER TABLE ONLY base_userlastlogin ALTER COLUMN id SET DEFAULT nextval('base_userlastlogin_id_seq'::regclass);



ALTER TABLE ONLY base_userstarredfiles ALTER COLUMN id SET DEFAULT nextval('base_userstarredfiles_id_seq'::regclass);



ALTER TABLE ONLY base_uuidobjidmap ALTER COLUMN id SET DEFAULT nextval('base_uuidobjidmap_id_seq'::regclass);



ALTER TABLE ONLY captcha_captchastore ALTER COLUMN id SET DEFAULT nextval('captcha_captchastore_id_seq'::regclass);



ALTER TABLE ONLY contacts_contact ALTER COLUMN id SET DEFAULT nextval('contacts_contact_id_seq'::regclass);



ALTER TABLE ONLY django_content_type ALTER COLUMN id SET DEFAULT nextval('django_content_type_id_seq'::regclass);



ALTER TABLE ONLY group_groupmessage ALTER COLUMN id SET DEFAULT nextval('group_groupmessage_id_seq'::regclass);



ALTER TABLE ONLY group_messageattachment ALTER COLUMN id SET DEFAULT nextval('group_messageattachment_id_seq'::regclass);



ALTER TABLE ONLY group_messagereply ALTER COLUMN id SET DEFAULT nextval('group_messagereply_id_seq'::regclass);



ALTER TABLE ONLY group_publicgroup ALTER COLUMN id SET DEFAULT nextval('group_publicgroup_id_seq'::regclass);



ALTER TABLE ONLY message_usermessage ALTER COLUMN message_id SET DEFAULT nextval('message_usermessage_message_id_seq'::regclass);



ALTER TABLE ONLY message_usermsgattachment ALTER COLUMN id SET DEFAULT nextval('message_usermsgattachment_id_seq'::regclass);



ALTER TABLE ONLY message_usermsglastcheck ALTER COLUMN id SET DEFAULT nextval('message_usermsglastcheck_id_seq'::regclass);



ALTER TABLE ONLY base_devicetoken ALTER COLUMN id SET DEFAULT nextval('base_devicetoken_id_seq'::regclass);



ALTER TABLE ONLY notifications_notification ALTER COLUMN id SET DEFAULT nextval('notifications_notification_id_seq'::regclass);



ALTER TABLE ONLY notifications_usernotification ALTER COLUMN id SET DEFAULT nextval('notifications_usernotification_id_seq'::regclass);



ALTER TABLE ONLY options_useroptions ALTER COLUMN id SET DEFAULT nextval('options_useroptions_id_seq'::regclass);



ALTER TABLE ONLY profile_detailedprofile ALTER COLUMN id SET DEFAULT nextval('profile_detailedprofile_id_seq'::regclass);



ALTER TABLE ONLY profile_profile ALTER COLUMN id SET DEFAULT nextval('profile_profile_id_seq'::regclass);



ALTER TABLE ONLY registration_registrationprofile ALTER COLUMN id SET DEFAULT nextval('registration_registrationprofile_id_seq'::regclass);



ALTER TABLE ONLY share_anonymousshare ALTER COLUMN id SET DEFAULT nextval('share_anonymousshare_id_seq'::regclass);



ALTER TABLE ONLY share_fileshare ALTER COLUMN id SET DEFAULT nextval('share_fileshare_id_seq'::regclass);



ALTER TABLE ONLY share_privatefiledirshare ALTER COLUMN id SET DEFAULT nextval('share_privatefiledirshare_id_seq'::regclass);



ALTER TABLE ONLY share_uploadlinkshare ALTER COLUMN id SET DEFAULT nextval('share_uploadlinkshare_id_seq'::regclass);



ALTER TABLE ONLY sysadmin_extra_userloginlog ALTER COLUMN id SET DEFAULT nextval('sysadmin_extra_userloginlog_id_seq'::regclass);



ALTER TABLE ONLY wiki_groupwiki ALTER COLUMN id SET DEFAULT nextval('wiki_groupwiki_id_seq'::regclass);



ALTER TABLE ONLY wiki_personalwiki ALTER COLUMN id SET DEFAULT nextval('wiki_personalwiki_id_seq'::regclass);



ALTER TABLE ONLY api2_token
    ADD CONSTRAINT api2_token_pkey PRIMARY KEY (key);

ALTER TABLE ONLY pubfile_grouppublicfile
    ADD CONSTRAINT pubfile_grouppublicfile_pkey PRIMARY KEY (id);


ALTER TABLE ONLY api2_token
    ADD CONSTRAINT api2_token_user_key UNIQUE ("user");



ALTER TABLE ONLY api2_tokenv2
    ADD CONSTRAINT api2_tokenv2_pkey PRIMARY KEY (key);



ALTER TABLE ONLY api2_tokenv2
    ADD CONSTRAINT api2_tokenv2_user_platform_device_id_key UNIQUE ("user", platform, device_id);



ALTER TABLE ONLY avatar_avatar
    ADD CONSTRAINT avatar_avatar_pkey PRIMARY KEY (id);



ALTER TABLE ONLY avatar_groupavatar
    ADD CONSTRAINT avatar_groupavatar_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_commandslastcheck
    ADD CONSTRAINT base_commandslastcheck_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_dirfileslastmodifiedinfo
    ADD CONSTRAINT base_dirfileslastmodifiedinfo_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_dirfileslastmodifiedinfo
    ADD CONSTRAINT base_dirfileslastmodifiedinfo_repo_id_parent_dir_hash_key UNIQUE (repo_id, parent_dir_hash);



ALTER TABLE ONLY base_filecontributors
    ADD CONSTRAINT base_filecontributors_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_filediscuss
    ADD CONSTRAINT base_filediscuss_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_filelastmodifiedinfo
    ADD CONSTRAINT base_filelastmodifiedinfo_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_filelastmodifiedinfo
    ADD CONSTRAINT base_filelastmodifiedinfo_repo_id_file_path_hash_key UNIQUE (repo_id, file_path_hash);



ALTER TABLE ONLY base_groupenabledmodule
    ADD CONSTRAINT base_groupenabledmodule_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_innerpubmsg
    ADD CONSTRAINT base_innerpubmsg_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_innerpubmsgreply
    ADD CONSTRAINT base_innerpubmsgreply_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_userenabledmodule
    ADD CONSTRAINT base_userenabledmodule_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_userlastlogin
    ADD CONSTRAINT base_userlastlogin_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_userstarredfiles
    ADD CONSTRAINT base_userstarredfiles_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_uuidobjidmap
    ADD CONSTRAINT base_uuidobjidmap_obj_id_key UNIQUE (obj_id);



ALTER TABLE ONLY base_uuidobjidmap
    ADD CONSTRAINT base_uuidobjidmap_pkey PRIMARY KEY (id);



ALTER TABLE ONLY captcha_captchastore
    ADD CONSTRAINT captcha_captchastore_hashkey_key UNIQUE (hashkey);



ALTER TABLE ONLY captcha_captchastore
    ADD CONSTRAINT captcha_captchastore_pkey PRIMARY KEY (id);



ALTER TABLE ONLY contacts_contact
    ADD CONSTRAINT contacts_contact_pkey PRIMARY KEY (id);



ALTER TABLE ONLY django_content_type
    ADD CONSTRAINT django_content_type_app_label_model_key UNIQUE (app_label, model);



ALTER TABLE ONLY django_content_type
    ADD CONSTRAINT django_content_type_pkey PRIMARY KEY (id);



ALTER TABLE ONLY django_session
    ADD CONSTRAINT django_session_pkey PRIMARY KEY (session_key);



ALTER TABLE ONLY group_groupmessage
    ADD CONSTRAINT group_groupmessage_pkey PRIMARY KEY (id);



ALTER TABLE ONLY group_messageattachment
    ADD CONSTRAINT group_messageattachment_pkey PRIMARY KEY (id);



ALTER TABLE ONLY group_messagereply
    ADD CONSTRAINT group_messagereply_pkey PRIMARY KEY (id);



ALTER TABLE ONLY group_publicgroup
    ADD CONSTRAINT group_publicgroup_pkey PRIMARY KEY (id);



ALTER TABLE ONLY message_usermessage
    ADD CONSTRAINT message_usermessage_pkey PRIMARY KEY (message_id);



ALTER TABLE ONLY message_usermsgattachment
    ADD CONSTRAINT message_usermsgattachment_pkey PRIMARY KEY (id);



ALTER TABLE ONLY message_usermsglastcheck
    ADD CONSTRAINT message_usermsglastcheck_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_devicetoken
    ADD CONSTRAINT base_devicetoken_pkey PRIMARY KEY (id);



ALTER TABLE ONLY base_devicetoken
    ADD CONSTRAINT base_devicetoken_token_user_key UNIQUE (token, "user");



ALTER TABLE ONLY notifications_notification
    ADD CONSTRAINT notifications_notification_pkey PRIMARY KEY (id);



ALTER TABLE ONLY notifications_usernotification
    ADD CONSTRAINT notifications_usernotification_pkey PRIMARY KEY (id);



ALTER TABLE ONLY options_useroptions
    ADD CONSTRAINT options_useroptions_pkey PRIMARY KEY (id);



ALTER TABLE ONLY profile_detailedprofile
    ADD CONSTRAINT profile_detailedprofile_pkey PRIMARY KEY (id);



ALTER TABLE ONLY profile_profile
    ADD CONSTRAINT profile_profile_pkey PRIMARY KEY (id);



ALTER TABLE ONLY profile_profile
    ADD CONSTRAINT profile_profile_user_key UNIQUE ("user");



ALTER TABLE ONLY registration_registrationprofile
    ADD CONSTRAINT registration_registrationprofile_pkey PRIMARY KEY (id);



ALTER TABLE ONLY share_anonymousshare
    ADD CONSTRAINT share_anonymousshare_pkey PRIMARY KEY (id);



ALTER TABLE ONLY share_anonymousshare
    ADD CONSTRAINT share_anonymousshare_token_key UNIQUE (token);



ALTER TABLE ONLY share_fileshare
    ADD CONSTRAINT share_fileshare_pkey PRIMARY KEY (id);



ALTER TABLE ONLY share_fileshare
    ADD CONSTRAINT share_fileshare_token_key UNIQUE (token);



ALTER TABLE ONLY share_orgfileshare
    ADD CONSTRAINT share_orgfileshare_file_share_id_key UNIQUE (file_share_id);



ALTER TABLE ONLY share_orgfileshare
    ADD CONSTRAINT share_orgfileshare_pkey PRIMARY KEY (id);



ALTER TABLE ONLY share_privatefiledirshare
    ADD CONSTRAINT share_privatefiledirshare_pkey PRIMARY KEY (id);



ALTER TABLE ONLY share_privatefiledirshare
    ADD CONSTRAINT share_privatefiledirshare_token_key UNIQUE (token);



ALTER TABLE ONLY share_uploadlinkshare
    ADD CONSTRAINT share_uploadlinkshare_pkey PRIMARY KEY (id);



ALTER TABLE ONLY share_uploadlinkshare
    ADD CONSTRAINT share_uploadlinkshare_token_key UNIQUE (token);



ALTER TABLE ONLY sysadmin_extra_userloginlog
    ADD CONSTRAINT sysadmin_extra_userloginlog_pkey PRIMARY KEY (id);



ALTER TABLE ONLY wiki_groupwiki
    ADD CONSTRAINT wiki_groupwiki_group_id_key UNIQUE (group_id);



ALTER TABLE ONLY wiki_groupwiki
    ADD CONSTRAINT wiki_groupwiki_pkey PRIMARY KEY (id);



ALTER TABLE ONLY wiki_personalwiki
    ADD CONSTRAINT wiki_personalwiki_pkey PRIMARY KEY (id);



ALTER TABLE ONLY wiki_personalwiki
    ADD CONSTRAINT wiki_personalwiki_username_key UNIQUE (username);



CREATE INDEX api2_token_key_like ON api2_token USING btree (key varchar_pattern_ops);



CREATE INDEX api2_token_user_like ON api2_token USING btree ("user" varchar_pattern_ops);



CREATE INDEX base_filecontributors_repo_id ON base_filecontributors USING btree (repo_id);



CREATE INDEX base_filecontributors_repo_id_like ON base_filecontributors USING btree (repo_id varchar_pattern_ops);



CREATE INDEX base_filediscuss_group_message_id ON base_filediscuss USING btree (group_message_id);



CREATE INDEX base_filediscuss_path_hash ON base_filediscuss USING btree (path_hash);



CREATE INDEX base_filediscuss_path_hash_like ON base_filediscuss USING btree (path_hash varchar_pattern_ops);



CREATE INDEX base_filelastmodifiedinfo_file_path_hash ON base_filelastmodifiedinfo USING btree (file_path_hash);



CREATE INDEX base_filelastmodifiedinfo_file_path_hash_like ON base_filelastmodifiedinfo USING btree (file_path_hash varchar_pattern_ops);



CREATE INDEX base_filelastmodifiedinfo_repo_id ON base_filelastmodifiedinfo USING btree (repo_id);

CREATE INDEX pubfile_grouppublicfile_group_id ON pubfile_grouppublicfile USING btree (group_id);


CREATE INDEX base_filelastmodifiedinfo_repo_id_like ON base_filelastmodifiedinfo USING btree (repo_id varchar_pattern_ops);



CREATE INDEX base_groupenabledmodule_group_id ON base_groupenabledmodule USING btree (group_id);



CREATE INDEX base_groupenabledmodule_group_id_like ON base_groupenabledmodule USING btree (group_id varchar_pattern_ops);



CREATE INDEX base_innerpubmsgreply_reply_to_id ON base_innerpubmsgreply USING btree (reply_to_id);



CREATE INDEX base_userenabledmodule_username ON base_userenabledmodule USING btree (username);



CREATE INDEX base_userenabledmodule_username_like ON base_userenabledmodule USING btree (username varchar_pattern_ops);



CREATE INDEX base_userlastlogin_username ON base_userlastlogin USING btree (username);



CREATE INDEX base_userlastlogin_username_like ON base_userlastlogin USING btree (username varchar_pattern_ops);



CREATE INDEX base_userstarredfiles_repo_id ON base_userstarredfiles USING btree (repo_id);



CREATE INDEX base_userstarredfiles_repo_id_like ON base_userstarredfiles USING btree (repo_id varchar_pattern_ops);



CREATE INDEX base_uuidobjidmap_obj_id_like ON base_uuidobjidmap USING btree (obj_id varchar_pattern_ops);



CREATE INDEX captcha_captchastore_hashkey_like ON captcha_captchastore USING btree (hashkey varchar_pattern_ops);



CREATE INDEX contacts_contact_user_email ON contacts_contact USING btree (user_email);



CREATE INDEX contacts_contact_user_email_like ON contacts_contact USING btree (user_email varchar_pattern_ops);



CREATE INDEX django_session_expire_date ON django_session USING btree (expire_date);



CREATE INDEX django_session_session_key_like ON django_session USING btree (session_key varchar_pattern_ops);



CREATE INDEX group_groupmessage_group_id ON group_groupmessage USING btree (group_id);



CREATE INDEX group_messageattachment_group_message_id ON group_messageattachment USING btree (group_message_id);



CREATE INDEX group_messagereply_reply_to_id ON group_messagereply USING btree (reply_to_id);



CREATE INDEX group_publicgroup_group_id ON group_publicgroup USING btree (group_id);



CREATE INDEX message_usermessage_from_email ON message_usermessage USING btree (from_email);



CREATE INDEX message_usermessage_from_email_like ON message_usermessage USING btree (from_email varchar_pattern_ops);



CREATE INDEX message_usermessage_to_email ON message_usermessage USING btree (to_email);



CREATE INDEX message_usermessage_to_email_like ON message_usermessage USING btree (to_email varchar_pattern_ops);



CREATE INDEX message_usermsgattachment_priv_file_dir_share_id ON message_usermsgattachment USING btree (priv_file_dir_share_id);



CREATE INDEX message_usermsgattachment_user_msg_id ON message_usermsgattachment USING btree (user_msg_id);



CREATE INDEX notifications_usernotification_msg_type ON notifications_usernotification USING btree (msg_type);



CREATE INDEX notifications_usernotification_msg_type_like ON notifications_usernotification USING btree (msg_type varchar_pattern_ops);



CREATE INDEX notifications_usernotification_to_user ON notifications_usernotification USING btree (to_user);



CREATE INDEX notifications_usernotification_to_user_like ON notifications_usernotification USING btree (to_user varchar_pattern_ops);



CREATE INDEX options_useroptions_email ON options_useroptions USING btree (email);



CREATE INDEX options_useroptions_email_like ON options_useroptions USING btree (email varchar_pattern_ops);



CREATE INDEX profile_detailedprofile_user ON profile_detailedprofile USING btree ("user");



CREATE INDEX profile_detailedprofile_user_like ON profile_detailedprofile USING btree ("user" varchar_pattern_ops);



CREATE INDEX profile_profile_user_like ON profile_profile USING btree ("user" varchar_pattern_ops);



CREATE INDEX share_anonymousshare_token_like ON share_anonymousshare USING btree (token varchar_pattern_ops);



CREATE INDEX share_fileshare_repo_id ON share_fileshare USING btree (repo_id);



CREATE INDEX share_fileshare_repo_id_like ON share_fileshare USING btree (repo_id varchar_pattern_ops);



CREATE INDEX share_fileshare_s_type ON share_fileshare USING btree (s_type);



CREATE INDEX share_fileshare_s_type_like ON share_fileshare USING btree (s_type varchar_pattern_ops);



CREATE INDEX share_fileshare_token_like ON share_fileshare USING btree (token varchar_pattern_ops);



CREATE INDEX share_fileshare_username ON share_fileshare USING btree (username);



CREATE INDEX share_fileshare_username_like ON share_fileshare USING btree (username varchar_pattern_ops);



CREATE INDEX share_privatefiledirshare_from_user ON share_privatefiledirshare USING btree (from_user);



CREATE INDEX share_privatefiledirshare_from_user_like ON share_privatefiledirshare USING btree (from_user varchar_pattern_ops);



CREATE INDEX share_privatefiledirshare_repo_id ON share_privatefiledirshare USING btree (repo_id);



CREATE INDEX share_privatefiledirshare_repo_id_like ON share_privatefiledirshare USING btree (repo_id varchar_pattern_ops);



CREATE INDEX share_privatefiledirshare_to_user ON share_privatefiledirshare USING btree (to_user);



CREATE INDEX share_privatefiledirshare_to_user_like ON share_privatefiledirshare USING btree (to_user varchar_pattern_ops);



CREATE INDEX share_privatefiledirshare_token_like ON share_privatefiledirshare USING btree (token varchar_pattern_ops);



CREATE INDEX share_uploadlinkshare_repo_id ON share_uploadlinkshare USING btree (repo_id);



CREATE INDEX share_uploadlinkshare_repo_id_like ON share_uploadlinkshare USING btree (repo_id varchar_pattern_ops);



CREATE INDEX share_uploadlinkshare_token_like ON share_uploadlinkshare USING btree (token varchar_pattern_ops);



CREATE INDEX share_uploadlinkshare_username ON share_uploadlinkshare USING btree (username);



CREATE INDEX share_uploadlinkshare_username_like ON share_uploadlinkshare USING btree (username varchar_pattern_ops);



CREATE INDEX sysadmin_extra_userloginlog_username ON sysadmin_extra_userloginlog USING btree (username);



CREATE INDEX sysadmin_extra_userloginlog_username_like ON sysadmin_extra_userloginlog USING btree (username varchar_pattern_ops);



CREATE INDEX sysadmin_extra_userloginlog_login_date ON sysadmin_extra_userloginlog USING btree (login_date);



CREATE INDEX wiki_personalwiki_username_like ON wiki_personalwiki USING btree (username varchar_pattern_ops);



ALTER TABLE ONLY base_innerpubmsgreply
    ADD CONSTRAINT base_innerpubmsgreply_reply_to_id_fkey FOREIGN KEY (reply_to_id) REFERENCES base_innerpubmsg(id) DEFERRABLE INITIALLY DEFERRED;



ALTER TABLE ONLY base_filediscuss
    ADD CONSTRAINT group_message_id_refs_id_c336ac2f FOREIGN KEY (group_message_id) REFERENCES group_groupmessage(id) DEFERRABLE INITIALLY DEFERRED;



ALTER TABLE ONLY group_messageattachment
    ADD CONSTRAINT group_messageattachment_group_message_id_fkey FOREIGN KEY (group_message_id) REFERENCES group_groupmessage(id) DEFERRABLE INITIALLY DEFERRED;



ALTER TABLE ONLY group_messagereply
    ADD CONSTRAINT group_messagereply_reply_to_id_fkey FOREIGN KEY (reply_to_id) REFERENCES group_groupmessage(id) DEFERRABLE INITIALLY DEFERRED;



ALTER TABLE ONLY message_usermsgattachment
    ADD CONSTRAINT message_usermsgattachment_user_msg_id_fkey FOREIGN KEY (user_msg_id) REFERENCES message_usermessage(message_id) DEFERRABLE INITIALLY DEFERRED;



ALTER TABLE ONLY message_usermsgattachment
    ADD CONSTRAINT priv_file_dir_share_id_refs_id_163f8f83 FOREIGN KEY (priv_file_dir_share_id) REFERENCES share_privatefiledirshare(id) DEFERRABLE INITIALLY DEFERRED;



ALTER TABLE ONLY share_orgfileshare
    ADD CONSTRAINT share_orgfileshare_file_share_id_fkey FOREIGN KEY (file_share_id) REFERENCES share_fileshare(id);

INSERT INTO django_content_type VALUES (1,'content type','contenttypes','contenttype'),(2,'session','sessions','session'),(3,'registration profile','registration','registrationprofile'),(4,'captcha store','captcha','captchastore'),(5,'token','api2','token'),(6,'token v2','api2','tokenv2'),(7,'avatar','avatar','avatar'),(8,'group avatar','avatar','groupavatar'),(9,'group enabled module','base','groupenabledmodule'),(10,'uuid objid map','base','uuidobjidmap'),(11,'inner pub msg reply','base','innerpubmsgreply'),(12,'commands last check','base','commandslastcheck'),(13,'user enabled module','base','userenabledmodule'),(14,'dir files last modified info','base','dirfileslastmodifiedinfo'),(15,'device token','base','devicetoken'),(16,'file last modified info','base','filelastmodifiedinfo'),(17,'file discuss','base','filediscuss'),(18,'inner pub msg','base','innerpubmsg'),(19,'file contributors','base','filecontributors'),(20,'user last login','base','userlastlogin'),(21,'user starred files','base','userstarredfiles'),(22,'contact','contacts','contact'),(23,'personal wiki','wiki','personalwiki'),(24,'group wiki','wiki','groupwiki'),(25,'public group','group','publicgroup'),(26,'group message','group','groupmessage'),(27,'message attachment','group','messageattachment'),(28,'message reply','group','messagereply'),(29,'user msg attachment','message','usermsgattachment'),(30,'user msg last check','message','usermsglastcheck'),(31,'user message','message','usermessage'),(32,'notification','notifications','notification'),(33,'user notification','notifications','usernotification'),(34,'user options','options','useroptions'),(35,'profile','profile','profile'),(36,'detailed profile','profile','detailedprofile'),(37,'private file dir share','share','privatefiledirshare'),(38,'upload link share','share','uploadlinkshare'),(39,'file share','share','fileshare'),(40,'anonymous share','share','anonymousshare'),(41,'org file share','share','orgfileshare'),(42,'group public file','pubfile','grouppublicfile'),(43,'user login log','sysadmin_extra','userloginlog');


REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;



