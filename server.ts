// Std libs
import {
  crypto,
  toHashString,
} from "https://deno.land/std@0.195.0/crypto/mod.ts";
import "https://deno.land/std@0.195.0/dotenv/load.ts";

// 3rd party libs
import { Command } from "https://deno.land/x/cliffy@v1.0.0-rc.3/command/mod.ts";
import {
  Application,
  Context,
  helpers,
  Router,
  RouterContext,
  Status,
} from "https://deno.land/x/oak@v12.6.0/mod.ts";
import {
  jwtVerify,
  SignJWT as jwtSign,
} from "https://deno.land/x/jose@v4.14.4/index.ts";

// Interfaces & types
interface User {
  uuid: string;
  name: string;
  email: string;
  password?: string;
  is_admin?: boolean;
}

type UserUpdated = Partial<User>;

interface Item {
  uuid: string;
  user_id: string;
  [key: string]: unknown;
}

type Collection = Item[];
type ItemUpdated = Partial<Item>;

interface LoginPayload {
  email: string;
  password: string;
}

// Utils
async function generate(password: string) {
  const a = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(password + salt),
  );
  return toHashString(a, "base64");
}

// Database
const kv = await Deno.openKv();
const salt = new TextEncoder().encode(Deno.env.get("SALT"));
const secret = new TextEncoder().encode(Deno.env.get("SECRET"));
const port = parseInt(Deno.env.get("PORT") || "8000");

async function getUsers() {
  const iter = kv.list<User>({ prefix: ["users"] });
  const users: User[] = [];
  for await (const res of iter) {
    delete res.value.password;
    users.push(res.value);
  }
  return users;
}

async function getUserByEmail(email: string) {
  const user = await kv.get<User>(["users_by_email", email]);
  return user.value;
}

async function createUser(user: UserUpdated) {
  if (!user.email) {
    throw new Error("Password is required");
  }
  if (!user.password) {
    throw new Error("Password is required");
  }
  // generate UUID for this user.
  const uuid = crypto.randomUUID();
  user.uuid = uuid;
  user.password = await generate(user.password);
  const primaryKey = ["users", user.uuid];
  const secondaryKey = ["users_by_email", user.email];
  const res = await kv.atomic()
    .check({ key: primaryKey, versionstamp: null })
    .check({ key: secondaryKey, versionstamp: null })
    .set(primaryKey, user)
    .set(secondaryKey, user)
    .commit();
  if (!res.ok) {
    throw new Error("Unable to create user");
  }
  return user;
}

async function addItem(collectionName: string, item: Item) {
  const uuid = crypto.randomUUID();
  item.uuid = uuid;
  const res = await kv.set([collectionName, uuid], item);
  if (!res.ok) {
    throw new Error("Unable to add item to collection");
  }
  return item;
}

async function getCollectionItems(collectionName: string) {
  const collection = kv.list<Item>({ prefix: [collectionName] });
  const items: Collection = [];
  for await (const item of collection) {
    items.push(item.value);
  }
  return items;
}

async function getItem(collectionName: string, uuid: string) {
  const item = await kv.get([collectionName, uuid]);
  return item.value!;
}

async function updateItem(
  collectionName: string,
  uuid: string,
  item: ItemUpdated,
) {
  const oldItem = await getItem(collectionName, uuid);
  if (!oldItem) return;
  item = { ...oldItem, ...item };
  item.uuid = uuid;
  item = Object.fromEntries(Object.entries(item).filter(([_, v]) => v != null));
  const _res = await kv.set([collectionName, uuid], item);
  return item;
}

async function deleteItem(collectionName: string, uuid: string) {
  await kv.delete([collectionName, uuid]);
  return;
}

async function deleteItems(collectionName: string) {
  const collection = kv.list<Item>({ prefix: [collectionName] });
  for await (const item of collection) {
    kv.delete(item.key);
  }
  return;
}

// Web server
const { getQuery } = helpers;
const app = new Application();
const apiRouter = new Router({ prefix: "/api/v1" });
const authRouter = new Router({ prefix: "/auth" });
const collectionsRouter = new Router({ prefix: "/collections" });

// Auth routes
authRouter.post("/register", async (context: RouterContext<"/register">) => {
  const body: UserUpdated = await context.request.body().value;
  const user: UserUpdated = await createUser(body);
  context.response.body = { user };
  context.response.status = 200;
});

authRouter.post("/login", async (context: RouterContext<"/login">) => {
  const body: LoginPayload = await context.request.body().value;
  const user: User | null = await getUserByEmail(body.email);
  const password = await generate(body.password);

  if (user && password === user.password) {
    const jwt = await new jwtSign({
      "uuid": user.uuid,
      "name": user.name,
      "email": user.email,
    })
      .setSubject(user.uuid)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setIssuer("urn:ignacio:server")
      .setAudience("urn:ignacio:app")
      .setExpirationTime("2h")
      .sign(secret);
    context.response.body = { data: { id_token: jwt } };
    context.cookies.set("id_token", jwt, { httpOnly: true });
  } else {
    context.response.body = { data: { message: "Unauthorize" } };
    context.response.status = 403;
  }
});

authRouter.get("/users", async (context: RouterContext<"/users">) => {
  const users = await getUsers();
  context.response.body = { data: { users } };
});

collectionsRouter.post(
  "/:collection",
  async (context: Context) => {
    const params = getQuery(context, { mergeParams: true });
    const item = await addItem(
      params.collection,
      await context.request.body().value,
    );
    context.response.body = {
      data: {
        ...item,
      },
    };
  },
);

collectionsRouter.delete(
  "/:collection",
  async (context: RouterContext<"/:collection">) => {
    const params = getQuery(context, { mergeParams: true });
    await deleteItems(params.collection);
    context.response.status = Status.NoContent;
  },
);

collectionsRouter.get(
  "/:collection/items",
  async (context: RouterContext<"/:collection/items">) => {
    const params = getQuery(context, { mergeParams: true });
    const items = await getCollectionItems(params.collection);
    context.response.body = {
      data: {
        [params.collection]: items,
      },
    };
  },
);

collectionsRouter.get(
  "/:collection/items/:uuid",
  async (context: RouterContext<"/:collection/items/:uuid">) => {
    const params = getQuery(context, { mergeParams: true });
    const item = await getItem(params.collection, params.uuid);
    if (!item) {
      context.response.status = 404;
    } else {
      context.response.body = {
        data: {
          ...item,
        },
      };
    }
  },
);

collectionsRouter.put(
  "/:collection/items/:uuid",
  async (context: RouterContext<"/:collection/items/:uuid">) => {
    const params = getQuery(context, { mergeParams: true });
    const item = await updateItem(
      params.collection,
      params.uuid,
      await context.request.body().value,
    );
    if (item) {
      context.response.body = {
        data: {
          ...item,
        },
      };
    } else {
      context.response.status = 404;
    }
  },
);

collectionsRouter.delete(
  "/:collection/items/:uuid",
  async (context: Context) => {
    const params = getQuery(context, { mergeParams: true });
    await deleteItem(params.collection, params.uuid);
    context.response.status = Status.NoContent;
  },
);

collectionsRouter.use(async (context: Context, next) => {
  const token = await context.cookies.get("id_token");
  if (!token) {
    context.response.status = 401;
    return;
  }
  try {
    const jwt = await jwtVerify(token, secret, {
      audience: "urn:ignacio:app",
      issuer: "urn:ignacio:server",
    });
    context.state.user = jwt.payload;
    await next();
  } catch (_err) {
    context.response.status = 401;
  }
});

app.use(async (context, next) => {
  try {
    await context.send({
      root: `${Deno.cwd()}/`,
      index: "index.html",
    });
  } catch {
    await next();
  }
});

apiRouter.use(authRouter.routes());
apiRouter.use(authRouter.allowedMethods());

apiRouter.use(collectionsRouter.routes());
apiRouter.use(collectionsRouter.allowedMethods());

app.use(apiRouter.routes());
app.use(apiRouter.allowedMethods());

const serve = new Command()
  .description("Serve app.")
  .action(() => {
    app.listen({ port });
  });

await new Command()
  .name("Milou backend server")
  .description("A simple backend server for fast prototyping.")
  .version("v0.0.1")
  .command("serve", serve)
  .parse(Deno.args);
