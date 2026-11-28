<script setup>
import { BOOT_FLAG, save } from '../storage';
import { useForm, Head } from '@inertiajs/vue3';
import BawlsMark from '../Components/BawlsMark.vue';

const props = defineProps({ errors: Object, loginUrl: String });

const form = useForm({
    email: '',
    password: '',
    remember: false,
});

function submit() {
    // The overview plays its boot sequence once, right after a sign-in.
    save(BOOT_FLAG, '1');
    form.post(props.loginUrl, {
        onFinish: () => form.reset('password'),
    });
}
</script>

<template>
    <Head title="Sign in" />

    <div class="flex min-h-screen items-center justify-center bg-void px-4">
        <div class="w-full max-w-sm">
            <div class="mb-6 flex items-center gap-3">
                <BawlsMark :size="30" />
                <div>
                    <h1 class="text-lg font-bold tracking-[0.3em] text-phosphor glow">BAWLS</h1>
                    <p class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">
                        Restricted console
                    </p>
                </div>
            </div>

            <form class="border border-grid bg-panel p-5" @submit.prevent="submit">
                <div
                    v-if="errors?.email"
                    class="mb-4 border border-alarm/50 bg-alarm/5 px-3 py-2 text-[0.8125rem] text-alarm"
                >
                    {{ errors.email }}
                </div>

                <label class="block">
                    <span class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">Address</span>
                    <input
                        v-model="form.email"
                        type="email"
                        autocomplete="username"
                        required
                        autofocus
                        class="mt-1 w-full border border-edge bg-void px-2 py-1.5 text-[0.875rem] text-ink outline-none focus:border-phosphor/60"
                    />
                </label>

                <label class="mt-4 block">
                    <span class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">Passphrase</span>
                    <input
                        v-model="form.password"
                        type="password"
                        autocomplete="current-password"
                        required
                        class="mt-1 w-full border border-edge bg-void px-2 py-1.5 text-[0.875rem] text-ink outline-none focus:border-phosphor/60"
                    />
                </label>

                <label class="mt-4 flex items-center gap-2 text-[0.8125rem] text-ink-dim">
                    <input v-model="form.remember" type="checkbox" class="accent-phosphor" />
                    Stay signed in
                </label>

                <button
                    type="submit"
                    :disabled="form.processing"
                    class="mt-5 w-full border border-phosphor/50 py-1.5 text-[0.8125rem] uppercase tracking-[0.2em] text-phosphor transition-colors hover:bg-phosphor/10 disabled:opacity-40"
                >
                    {{ form.processing ? 'Verifying…' : 'Sign in' }}
                </button>
            </form>

            <p class="mt-4 text-center text-[0.75rem] text-ink-faint">
                Accounts are issued from the CLI — there is no sign-up.
            </p>
        </div>
    </div>
</template>
