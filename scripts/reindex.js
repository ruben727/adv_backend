// scripts/reindex.js
// Recrea el índice de Elasticsearch y carga predicas + avisos desde Postgres,
// más las páginas estáticas del sitio. Se corre a mano: node scripts/reindex.js

require('dotenv').config();

const { Pool } = require('pg');
const { Client: ElasticClient } = require('@elastic/elasticsearch');

const ES_INDEX = process.env.ELASTIC_INDEX || 'busqueda';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const es = new ElasticClient({ node: process.env.ELASTIC_NODE || 'http://localhost:9200' });

const PAGINAS_ESTATICAS = [
  {
    id: 'inicio',
    titulo: 'Inicio - Agua de Vida',
    descripcion: 'Página principal de la iglesia Agua de Vida. Bienvenidos a nuestra comunidad.',
    route: '/',
    keywords: ['inicio', 'home', 'principal', 'iglesia', 'agua de vida', 'bienvenidos', 'comunidad']
  },
  {
    id: 'predicas-page',
    titulo: 'Prédicas y Sermones',
    descripcion: 'Escucha y descubre todos los sermones y prédicas de la iglesia.',
    route: '/predicas',
    keywords: ['predicas', 'sermones', 'mensaje', 'predicar', 'palabra', 'biblia', 'enseñanza']
  },
  {
    id: 'avisos-page',
    titulo: 'Avisos y Anuncios',
    descripcion: 'Avisos importantes, eventos y noticias de nuestra comunidad.',
    route: '/avisos',
    keywords: ['avisos', 'anuncios', 'eventos', 'noticias', 'comunicados', 'reunión']
  },
  {
    id: 'contacto-page',
    titulo: 'Contacto',
    descripcion: 'Dirección, teléfono y formas de contactar a la iglesia Agua de Vida.',
    route: '/contacto',
    keywords: ['contacto', 'dirección', 'teléfono', 'correo', 'ubicación', 'mapa', 'encontrar', 'llegar']
  }
];

function formatFecha(fecha) {
  if (!fecha) return '';
  try {
    return new Date(fecha).toLocaleDateString('es-MX', { day: '2-digit', month: 'short', year: 'numeric' });
  } catch {
    return '';
  }
}

const MAPPING = {
  settings: {
    analysis: {
      filter: {
        spanish_stemmer: { type: 'stemmer', language: 'light_spanish' }
      },
      analyzer: {
        spanish_folding: {
          tokenizer: 'standard',
          filter: ['lowercase', 'asciifolding', 'spanish_stemmer']
        }
      }
    }
  },
  mappings: {
    properties: {
      tipo: { type: 'keyword' },
      titulo: { type: 'text', analyzer: 'spanish_folding', fields: { keyword: { type: 'keyword' } } },
      predicador: { type: 'text', analyzer: 'spanish_folding' },
      descripcion: { type: 'text', analyzer: 'spanish_folding' },
      contenido: { type: 'text', analyzer: 'spanish_folding' },
      route: { type: 'keyword' },
      extraInfo: { type: 'keyword' },
      fecha: { type: 'date' },
      activo: { type: 'boolean' }
    }
  }
};

async function reindex() {
  const exists = await es.indices.exists({ index: ES_INDEX });
  if (exists) {
    await es.indices.delete({ index: ES_INDEX });
    console.log(`Índice "${ES_INDEX}" eliminado.`);
  }
  await es.indices.create({ index: ES_INDEX, ...MAPPING });
  console.log(`Índice "${ES_INDEX}" creado.`);

  const operations = [];

  const { rows: predicas } = await pool.query('SELECT * FROM predicas');
  for (const p of predicas) {
    operations.push({ index: { _index: ES_INDEX, _id: `predica-${p.id}` } });
    operations.push({
      tipo: 'predica',
      titulo: p.titulo,
      predicador: p.predicador,
      descripcion: `Predicador: ${p.predicador}`,
      contenido: '',
      route: '/predicas',
      extraInfo: formatFecha(p.fecha),
      fecha: p.fecha,
      activo: p.activo
    });
  }

  const { rows: avisos } = await pool.query('SELECT * FROM avisos');
  for (const a of avisos) {
    operations.push({ index: { _index: ES_INDEX, _id: `aviso-${a.id}` } });
    operations.push({
      tipo: 'aviso',
      titulo: a.titulo,
      predicador: '',
      descripcion: a.descripcion,
      contenido: '',
      route: '/avisos',
      extraInfo: formatFecha(a.fecha),
      fecha: a.fecha,
      activo: a.activo
    });
  }

  for (const page of PAGINAS_ESTATICAS) {
    operations.push({ index: { _index: ES_INDEX, _id: page.id } });
    operations.push({
      tipo: 'pagina',
      titulo: page.titulo,
      predicador: '',
      descripcion: page.descripcion,
      contenido: page.keywords.join(' '),
      route: page.route,
      extraInfo: '',
      fecha: null,
      activo: true
    });
  }

  if (operations.length > 0) {
    const bulkResult = await es.bulk({ refresh: true, operations });
    if (bulkResult.errors) {
      const failed = bulkResult.items.filter(item => item.index?.error);
      console.error('Errores al indexar:', JSON.stringify(failed, null, 2));
    }
  }

  console.log(`Indexado: ${predicas.length} predicas, ${avisos.length} avisos, ${PAGINAS_ESTATICAS.length} páginas estáticas.`);
}

reindex()
  .then(() => pool.end())
  .catch(err => {
    console.error('Error en reindex:', err);
    pool.end();
    process.exit(1);
  });
