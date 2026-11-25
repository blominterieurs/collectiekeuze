-- Gebruikersbeheer rechtgetrokken: één centrale gebruikerslijst met toegang per app.
-- Plak dit hele bestand in de SQL-editor van Supabase (project Database V1) en klik op Run.
-- Alles gebeurt in één keer: gaat er iets mis, dan verandert er niets.
--
--   gebruikersbeheer.gebruikers     : alle accounts (was app.gebruikers). beheerder = ziet en beheert alles.
--   gebruikersbeheer.apps           : de apps. met_rol = toegang gaat via een rol binnen de app (Collectiekeuze).
--   gebruikersbeheer.zichtbaarheid  : per persoon en app: zichtbaar of niet, en de rol binnen die app.
--   gebruikersbeheer.wachtwoord_log : bestaat al; hier komt het overzicht wachtwoord_stand bij.
-- Voor de Collectiekeuze verandert er niets aan wie wat mag.

begin;

-- 1. de gebruikerslijst verhuist
alter table app.gebruikers set schema gebruikersbeheer;
alter table gebruikersbeheer.gebruikers add column beheerder boolean not null default false;
update gebruikersbeheer.gebruikers set beheerder = (rol = 'beheerder');
revoke all on gebruikersbeheer.gebruikers from public, anon, authenticated;

-- 2. de Collectiekeuze wordt een app; de rol van nu wordt de toegang tot die app
alter table gebruikersbeheer.apps add column met_rol boolean not null default false;
insert into gebruikersbeheer.apps (code, naam, met_rol) values ('collectiekeuze', 'Collectiekeuze', true);

alter table gebruikersbeheer.zichtbaarheid add column rol text
  check (rol is null or rol in ('beoordelaar', 'beoordelaar_zonder_prijzen'));

insert into gebruikersbeheer.zichtbaarheid (email, app, zichtbaar, rol, bijgewerkt_door)
  select email, 'collectiekeuze', true, rol, 'migratie' from gebruikersbeheer.gebruikers where not beheerder;

-- 3. de oude kolom rol is nu overbodig
alter table gebruikersbeheer.gebruikers drop column rol;

-- 4. functies die bepalen wie wat mag

-- heeft de ingelogde persoon een account?
create function public.is_gebruiker()
returns boolean language sql stable security definer set search_path = ''
as $$
  select coalesce(lower(auth.jwt() ->> 'email') like '%@blominterieurs.nl', false)
     and exists (select 1 from gebruikersbeheer.gebruikers g where g.email = lower(auth.jwt() ->> 'email'))
$$;

-- rol in de Collectiekeuze: beheerder, beoordelaar, beoordelaar_zonder_prijzen of null (geen toegang)
create or replace function public.mijn_rol_tekst()
returns text language sql stable security definer set search_path = ''
as $$
  select case when g.beheerder then 'beheerder'
              else (select z.rol from gebruikersbeheer.zichtbaarheid z
                    where z.email = g.email and z.app = 'collectiekeuze' and z.zichtbaar) end
  from gebruikersbeheer.gebruikers g where g.email = lower(auth.jwt() ->> 'email')
$$;

-- zelfde als voorheen: null voor wie geen toegang tot de Collectiekeuze heeft
create or replace function public.mijn_rol()
returns jsonb language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object('email', g.email, 'naam', g.naam, 'rol', public.mijn_rol_tekst())
  from gebruikersbeheer.gebruikers g
  where g.email = lower(auth.jwt() ->> 'email') and public.mijn_rol_tekst() is not null
$$;

create or replace function public.mag_app(p_app text)
returns boolean language sql stable security definer set search_path = ''
as $$
  select coalesce(public.is_gebruiker(), false)
     and (public.is_beheerder()
          or exists (select 1 from gebruikersbeheer.zichtbaarheid z
                     where z.email = lower(auth.jwt() ->> 'email') and z.app = p_app and z.zichtbaar))
$$;

-- voor de startpagina: wie ben ik en welke apps zie ik
create function public.mijn_account()
returns jsonb language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object('email', g.email, 'naam', g.naam, 'beheerder', g.beheerder, 'apps', public.mijn_apps())
  from gebruikersbeheer.gebruikers g where g.email = lower(auth.jwt() ->> 'email')
$$;

-- gebruikersscherm: rol = rol in de Collectiekeuze, of 'geen'
create or replace function public.gebruikers_lijst()
returns table (email text, naam text, rol text, toegevoegd_op timestamptz, laatst_ingelogd timestamptz)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not public.is_beheerder() then raise exception 'not_granted' using errcode = '42501'; end if;
  return query
    select g.email, g.naam,
           case when g.beheerder then 'beheerder'
                else coalesce((select z.rol from gebruikersbeheer.zichtbaarheid z
                               where z.email = g.email and z.app = 'collectiekeuze' and z.zichtbaar), 'geen') end,
           g.toegevoegd_op, u.last_sign_in_at
    from gebruikersbeheer.gebruikers g left join auth.users u on lower(u.email) = g.email
    order by (not g.beheerder), g.email;
end $$;

-- p_rol: 'beheerder', 'beoordelaar', 'beoordelaar_zonder_prijzen' of 'geen' (account zonder Collectiekeuze)
create or replace function public.gebruiker_zet(p_email text, p_naam text, p_rol text)
returns void language plpgsql security definer set search_path = ''
as $$
declare e text := lower(btrim(p_email)); wie text := lower(auth.jwt() ->> 'email');
begin
  if not public.is_beheerder() then raise exception 'not_granted' using errcode = '42501'; end if;
  if e not like '%_@blominterieurs.nl' then raise exception 'Alleen @blominterieurs.nl-adressen' using errcode = '22023'; end if;
  if p_rol not in ('beheerder', 'beoordelaar', 'beoordelaar_zonder_prijzen', 'geen') then raise exception 'Onbekende rol %', p_rol using errcode = '22023'; end if;
  if p_rol <> 'beheerder' and exists (select 1 from gebruikersbeheer.gebruikers where email = e and beheerder)
     and (select count(*) from gebruikersbeheer.gebruikers where beheerder) <= 1 then
    raise exception 'Er moet minstens één beheerder blijven' using errcode = '22023';
  end if;
  insert into gebruikersbeheer.gebruikers as g (email, naam, beheerder, toegevoegd_door)
  values (e, nullif(btrim(p_naam), ''), p_rol = 'beheerder', wie)
  on conflict (email) do update set naam = coalesce(nullif(btrim(p_naam), ''), g.naam), beheerder = excluded.beheerder;
  if p_rol in ('beoordelaar', 'beoordelaar_zonder_prijzen') then
    insert into gebruikersbeheer.zichtbaarheid (email, app, zichtbaar, rol, bijgewerkt_door) values (e, 'collectiekeuze', true, p_rol, wie)
    on conflict (email, app) do update set zichtbaar = true, rol = excluded.rol, bijgewerkt_op = now(), bijgewerkt_door = wie;
  elsif p_rol = 'geen' then
    update gebruikersbeheer.zichtbaarheid set zichtbaar = false, bijgewerkt_op = now(), bijgewerkt_door = wie
    where email = e and app = 'collectiekeuze';
  end if;
end $$;

create or replace function public.gebruiker_verwijder(p_email text)
returns void language plpgsql security definer set search_path = ''
as $$
declare e text := lower(btrim(p_email));
begin
  if not public.is_beheerder() then raise exception 'not_granted' using errcode = '42501'; end if;
  if e = lower(auth.jwt() ->> 'email') then raise exception 'Je kunt jezelf niet verwijderen' using errcode = '22023'; end if;
  delete from gebruikersbeheer.gebruikers where email = e;   -- de zichtbaarheid van deze persoon gaat vanzelf mee
end $$;

-- vinkjes in het gebruikersscherm: alleen apps zonder eigen rol
create or replace function public.zichtbaarheid_lijst()
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
begin
  if not public.is_beheerder() then raise exception 'not_granted' using errcode = '42501'; end if;
  return jsonb_build_object(
    'apps', coalesce((select jsonb_agg(jsonb_build_object('code', code, 'naam', naam) order by naam) from gebruikersbeheer.apps where not met_rol), '[]'::jsonb),
    'zichtbaar', coalesce((select jsonb_object_agg(email, apps) from (
        select email, jsonb_agg(app order by app) as apps from gebruikersbeheer.zichtbaarheid where zichtbaar group by email) x), '{}'::jsonb));
end $$;

create or replace function public.zichtbaarheid_zet(p_email text, p_app text, p_zichtbaar boolean)
returns void language plpgsql security definer set search_path = ''
as $$
declare e text := lower(btrim(p_email));
begin
  if not public.is_beheerder() then raise exception 'not_granted' using errcode = '42501'; end if;
  if not exists (select 1 from gebruikersbeheer.gebruikers where email = e) then raise exception 'Onbekende gebruiker %', e using errcode = '22023'; end if;
  if not exists (select 1 from gebruikersbeheer.apps where code = p_app and not met_rol) then raise exception 'Onbekende app %, of een app waarvan je de toegang via de rol instelt', p_app using errcode = '22023'; end if;
  insert into gebruikersbeheer.zichtbaarheid as z (email, app, zichtbaar, bijgewerkt_door)
  values (e, p_app, coalesce(p_zichtbaar, false), lower(auth.jwt() ->> 'email'))
  on conflict (email, app) do update set zichtbaar = excluded.zichtbaar, bijgewerkt_op = now(), bijgewerkt_door = excluded.bijgewerkt_door;
end $$;

revoke all on function public.is_gebruiker(), public.mijn_account() from public, anon;
grant execute on function public.is_gebruiker(), public.mijn_account() to authenticated;

-- 5. overzicht voor in de tabelweergave: wie zit nog op een ingesteld wachtwoord
create view gebruikersbeheer.wachtwoord_stand with (security_invoker = true) as
  select g.email, g.naam,
         case when u.id is null then 'nog geen account'
              when coalesce(u.raw_user_meta_data ->> 'wachtwoord_wijzigen', 'false') = 'true' then 'moet nog een eigen wachtwoord kiezen'
              else 'eigen wachtwoord' end as stand,
         l.gebeurtenis as laatste_gebeurtenis, l.door as laatste_door, l.op as laatste_op
  from gebruikersbeheer.gebruikers g
  left join auth.users u on lower(u.email) = g.email
  left join lateral (select w.gebeurtenis, w.door, w.op from gebruikersbeheer.wachtwoord_log w
                     where w.email = g.email order by w.op desc limit 1) l on true;
revoke all on gebruikersbeheer.wachtwoord_stand from public, anon, authenticated;

-- 6. opruimen van wat niet meer gebruikt wordt
drop table if exists kerstkaarten_2026.gebruikers;
drop function if exists public.kerstkaarten_2026_inladen(text, text, jsonb);
delete from kerstkaarten_2026.aangepaste_kaarten where id = 'kea94f9aed9';

commit;

-- Controle: iedereen met de toegang die hij nu heeft
select g.email, g.naam, g.beheerder,
       (select string_agg(z.app || coalesce(' (' || z.rol || ')', ''), ', ' order by z.app)
        from gebruikersbeheer.zichtbaarheid z where z.email = g.email and z.zichtbaar) as apps
from gebruikersbeheer.gebruikers g order by (not g.beheerder), g.email;
