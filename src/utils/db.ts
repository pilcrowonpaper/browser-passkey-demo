type Schema = {
	id: string;
	username: string;
	credential_id: string;
	public_key: string;
};

class Database {
	private internal: Map<string, Schema>;
	private eventListeners: ((db: Database) => void)[] = [];
	private static key = "user";

	private commit(): void {
		window.localStorage.setItem(
			Database.key,
			JSON.stringify(Array.from(this.internal.entries())),
		);
		for (const eventListener of this.eventListeners) {
			eventListener(this);
		}
	}

	constructor() {
		const storedData = window.localStorage.getItem(Database.key) ?? null;
		if (storedData) {
			const storedEntries = JSON.parse(storedData) as [string, Schema][];
			this.internal = new Map(storedEntries);
		} else {
			this.internal = new Map();
		}
	}

	public insert(data: Schema): Schema {
		for (const [id, entry] of this.internal.entries()) {
			if (data.id === id) throw new Error("Unique constraint failed on 'id'");
			if (data.username === entry.username) {
				throw new Error("Unique constraint failed on 'username'");
			}
			if (data.credential_id === entry.credential_id) {
				throw new Error("Unique constraint failed on 'credential_id'");
			}
		}
		this.internal.set(data.id, data);
		this.commit();
		return data;
	}

	public get(id: string): Schema | null {
		return this.internal.get(id) ?? null;
	}

	public getByCredentialId(credentialId: string): Schema | null {
		for (const entry of this.internal.values()) {
			if (entry.credential_id === credentialId) return entry;
		}
		return null;
	}

	public getByUsername(username: string): Schema | null {
		for (const entry of this.internal.values()) {
			if (entry.username === username) return entry;
		}
		return null;
	}

	public remove(id: string): void {
		this.internal.delete(id);
		this.commit();
	}

	public update(id: string, data: Partial<Schema>): Schema {
		const storedData = this.get(id);
		if (!storedData) throw new Error("Entry does not exist");
		const updatedData = {
			...storedData,
			...data,
		};
		this.internal.set(id, updatedData);
		this.commit();
		return updatedData;
	}

	public clear(): void {
		this.internal.clear();
		this.commit();
	}

	public entries(): Schema[] {
		return Array.from(this.internal.values());
	}

	public onUpdate(callback: (db: Database) => void): void {
		this.eventListeners.push(callback);
	}
}

export const db = new Database();
