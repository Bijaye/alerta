
CREATE TYPE history AS (
    id uuid,
    event text,
    severity text,
    status text,
    value text,
    text text,
    type text,
    update_time timestamp
);

CREATE TABLE alerts (
    id uuid NOT NULL,
    resource text NOT NULL,
    event text NOT NULL,
    environment text NOT NULL,
    severity text NOT NULL,
    correlate text[],
    status text NOT NULL,
    service text[],
    "group" text,
    value text,
    text text,
    tags text[],
    attributes text[][],
    origin text,
    type text,
    create_time timestamp,
    timeout integer,
    raw_data text,
    customer text,
    duplicate_count integer,
    repeat boolean,

    previous_severity text,
    trend_indication text,
    receive_time timestamp,
    last_receive_id uuid NOT NULL,
    last_receive_time timestamp,
    history history[]
);

ALTER TABLE ONLY alerts
    ADD CONSTRAINT id_pkey PRIMARY KEY (id),
    ADD CONSTRAINT env_res_evt UNIQUE (environment, resource, event);